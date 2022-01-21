package io.projectdiscovery.nuclei.util;

import burp.IResponseInfo;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

public class Utils {

    private static final char CR = '\r';
    private static final char LF = '\n';
    private static final String CRLF = "" + CR + LF;

    private static final char INTRUDER_PAYLOAD_MARKER = '§';
    private static final Pattern INTRUDER_PAYLOAD_PATTERN = Pattern.compile(String.format("(%1$s.*?%1$s)", INTRUDER_PAYLOAD_MARKER), Pattern.DOTALL);

    private static final String BASE_PAYLOAD_PARAMETER_NAME = "param";
    private static final String PAYLOAD_START_MARKER = "{{";
    private static final String PAYLOAD_END_MARKER = "}}";

    public static String dumpYaml(Object data) {
        final Representer representer = new Representer() {
            @Override
            protected NodeTuple representJavaBeanProperty(Object javaBean, Property property, Object propertyValue, Tag customTag) {
                if (Objects.isNull(propertyValue)) {
                    return null; // skip fields with null value
                }
                return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
            }

            @Override
            protected MappingNode representJavaBean(Set<Property> properties, Object javaBean) {
                if (!classTags.containsKey(javaBean.getClass())) {
                    addClassTag(javaBean.getClass(), Tag.MAP);
                }

                return super.representJavaBean(properties, javaBean);
            }
        };

        final TypeDescription typeDescription = new TypeDescription(Requests.class, Tag.MAP);
        // TODO isn't there a more elegant way to remap field names?
        typeDescription.substituteProperty("matchers-condition", Requests.class, "getMatchersCondition", "setMatchersCondition");
        typeDescription.setExcludes("matchersCondition");
        representer.addTypeDescription(typeDescription);

        final DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        final Yaml yaml = new Yaml(representer, options);
        return yaml.dumpAsMap(data);
    }

    public static void executeCommand(String command, Consumer<BufferedReader> processOutputConsumer, Consumer<Integer> exitCodeConsumer, Consumer<String> errorHandler) {
        final String[] commandParts = command.split(" "); // TODO handle space between quotes
        executeCommand(commandParts, processOutputConsumer, exitCodeConsumer, errorHandler);
    }

    public static void executeCommand(String[] command, Consumer<BufferedReader> processOutputConsumer, Consumer<Integer> exitCodeConsumer, Consumer<String> errorHandler) {
        final ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        final Future<Integer> commandFuture = Executors.newSingleThreadExecutor().submit(() -> {
            final Process process;
            try {
                process = processBuilder.start();
                process.getOutputStream().close(); // close the process's input stream, because otherwise it will hang waiting for an input

                try (final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    processOutputConsumer.accept(bufferedReader);
                }

                return process.waitFor();
            } catch (InterruptedException | IOException ex) {
                errorHandler.accept(ex.getMessage());
                return -1;
            }
        });

        Executors.newSingleThreadExecutor().submit(() -> {
            int commandCode;
            try {
                commandCode = commandFuture.get();
            } catch (InterruptedException | ExecutionException e) {
                commandCode = -1;
                errorHandler.accept(e.getMessage());
            }

            exitCodeConsumer.accept(commandCode);
        });
    }

    public static void writeToFile(String content, Path filePath, Consumer<String> logger) {
        try (final FileWriter fileWriter = new FileWriter(filePath.toFile())) {
            fileWriter.write(content);
            fileWriter.flush();
        } catch (Exception e) {
            logger.accept(String.format("Error while writing to file '%s': %s ", filePath, e.getMessage()));
        }
    }

    public static boolean isAsciiPrintableNewLine(byte[] input) {
        return IntStream.range(0, input.length).map(i -> input[i]).allMatch(b -> b == CR || b == LF || (b >= 20 && b < 0x7F));
    }

    public static TemplateMatcher.Part getSelectionPart(IResponseInfo responseInfo, int fromIndex) {
        final int bodyOffset = responseInfo.getBodyOffset();
        return (bodyOffset != -1) && (fromIndex < bodyOffset) ? TemplateMatcher.Part.header : TemplateMatcher.Part.body;
    }

    public static TemplateMatcher createContentMatcher(byte[] responseBytes, IResponseInfo responseInfo, int[] selectionBounds) {
        final int fromIndex = selectionBounds[0];
        final int toIndex = selectionBounds[1];

        final byte[] selectedBytes = Arrays.copyOfRange(responseBytes, fromIndex, toIndex);
        final TemplateMatcher.Part selectionPart = Utils.getSelectionPart(responseInfo, fromIndex);

        final TemplateMatcher contentMatcher;
        if (Utils.isAsciiPrintableNewLine(selectedBytes)) {
            contentMatcher = createWordMatcher(responseBytes, fromIndex, toIndex, selectionPart);
        } else {
            final Binary binaryMatcher = new Binary(selectedBytes);
            binaryMatcher.setPart(selectionPart);
            contentMatcher = binaryMatcher;
        }

        return contentMatcher;
    }

    public static TransformedRequest transformRequestWithPayloads(Requests.AttackType attackType, String request) {
        final Matcher matcher = INTRUDER_PAYLOAD_PATTERN.matcher(request);

        if (attackType == Requests.AttackType.batteringram) {
            final List<String> payloadParameters = new ArrayList<>();
            final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
                payloadParameters.add(payloadParameter);
                return BASE_PAYLOAD_PARAMETER_NAME;
            };

            String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
            return new TransformedRequest(attackType, transformedRequest, Map.of(BASE_PAYLOAD_PARAMETER_NAME, payloadParameters));
        } else {
            final Map<String, List<String>> payloadParameters = new LinkedHashMap<>();

            final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
                final String indexedParameterName = BASE_PAYLOAD_PARAMETER_NAME + index;
                payloadParameters.put(indexedParameterName, new ArrayList<>(List.of(payloadParameter)));
                return indexedParameterName;
            };

            final String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
            return new TransformedRequest(attackType, transformedRequest, payloadParameters);
        }
    }

    private static String transformRawRequest(String request, Matcher matcher, BiFunction<Integer, String, String> payloadFunction) {
        String transformedRequest = request;
        int index = 1;
        while (matcher.find()) {
            final String group = matcher.group();
            final String payloadParameter = group.substring(1, group.length() - 1);

            final String newParamName = payloadFunction.apply(index++, payloadParameter);

            transformedRequest = transformedRequest.replace(group, PAYLOAD_START_MARKER + newParamName + PAYLOAD_END_MARKER);
        }
        return transformedRequest;
    }

    private static TemplateMatcher createWordMatcher(byte[] responseBytes, int fromIndex, int toIndex, TemplateMatcher.Part selectionPart) {
        final String selectedString = new String(Arrays.copyOfRange(responseBytes, fromIndex, toIndex)); // TODO charset Charset.defaultCharset() vs UTF-8

        final Word wordMatcher;
        if (selectionPart == TemplateMatcher.Part.header) {
            wordMatcher = new Word(selectedString.split(CRLF));
        } else {
            // TODO could make a config to enable the user to decide on the normalization
            final String selectedStringWithNormalizedNewLines = selectedString.replaceAll(CRLF, String.valueOf(LF)).replace(CR, LF);
            wordMatcher = new Word(selectedStringWithNormalizedNewLines.split(String.valueOf(LF)));
        }
        wordMatcher.setPart(selectionPart);
        return wordMatcher;
    }
}
