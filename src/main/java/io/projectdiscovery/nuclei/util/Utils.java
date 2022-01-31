package io.projectdiscovery.nuclei.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import io.projectdiscovery.nuclei.gui.SettingsPanel;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.awt.*;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public final class Utils {

    private static final char CR = '\r';
    private static final char LF = '\n';
    private static final String CRLF = "" + CR + LF;

    public static final char INTRUDER_PAYLOAD_MARKER = '§';
    private static final Pattern INTRUDER_PAYLOAD_PATTERN = Pattern.compile(String.format("(%1$s.*?%1$s)", INTRUDER_PAYLOAD_MARKER), Pattern.DOTALL);

    private static final String BASE_PAYLOAD_PARAMETER_NAME = "param";
    private static final String PAYLOAD_START_MARKER = "{{";
    private static final String PAYLOAD_END_MARKER = "}}";

    private Utils() {
    }

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
                if (!this.classTags.containsKey(javaBean.getClass())) {
                    addClassTag(javaBean.getClass(), Tag.MAP);
                }

                return super.representJavaBean(properties, javaBean);
            }

            @Override
            protected Set<Property> getProperties(Class<?> type) {
                Set<Property> propertySet = this.typeDefinitions.containsKey(type) ? this.typeDefinitions.get(type).getProperties()
                                                                                   : super.getPropertyUtils().getProperties(type);

                final YamlPropertyOrder annotation = type.getAnnotation(YamlPropertyOrder.class);
                if (annotation != null) {
                    final List<String> order = Arrays.asList(annotation.value());
                    propertySet = propertySet.stream()
                                             .sorted(Comparator.comparingInt(o -> order.indexOf(o.getName())))
                                             .collect(Collectors.toCollection(LinkedHashSet::new));
                }

                return propertySet;
            }
        };

        // TODO isn't there a more elegant way to remap field names?
        Map.of(
                Requests.class, List.of("matchersCondition"),
                Info.Classification.class, List.of("cvssMetrics", "cvssScore", "cveId", "cweId")
        ).forEach((clazz, fields) -> {
            final TypeDescription requestsTypeDescription = new TypeDescription(clazz, Tag.MAP);
            fields.forEach(field -> requestsTypeDescription.substituteProperty(toSnakeCase(field), Info.Classification.class, createGetterMethodName(field), createSetterMethodName(field)));
            requestsTypeDescription.setExcludes(fields.toArray(String[]::new));
            representer.addTypeDescription(requestsTypeDescription);
        });

        final DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        final Yaml yaml = new Yaml(representer, options);
        return yaml.dumpAsMap(data);
    }

    private static String createGetterOrSetterMethodName(String prefix, String fieldName) {
        return prefix + String.valueOf(fieldName.charAt(0)).toUpperCase() + fieldName.substring(1);
    }

    public static void executeCommand(String command, Consumer<BufferedReader> processOutputConsumer, Consumer<Integer> exitCodeConsumer, Consumer<String> errorHandler) {
        final String[] commandParts = stringCommandToChunks(command);
        executeCommand(commandParts, processOutputConsumer, exitCodeConsumer, errorHandler);
    }

    static String[] stringCommandToChunks(String command) {
        return command.replaceAll("^\"", "")
                      .split("\"?( |$)(?=(([^\"]*\"){2})*[^\"]*$)\"?");
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

    public static boolean writeToFile(String content, Path filePath, Consumer<String> logger) {
        try (final FileWriter fileWriter = new FileWriter(filePath.toFile())) {
            fileWriter.write(content);
            fileWriter.flush();
            return true;
        } catch (Exception e) {
            logger.accept(String.format("Error while writing to file '%s': %s ", filePath, e.getMessage()));
            return false;
        }
    }

    public static void openWebPage(String url) throws IOException, URISyntaxException {
        openWebPage(new URL(url).toURI());
    }

    public static void openWebPage(URL url) throws IOException, URISyntaxException {
        openWebPage(url.toURI());
    }

    public static void openWebPage(URI uri) throws IOException {
        final Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            desktop.browse(uri);
        }
    }

    public static boolean isAsciiPrintableNewLine(byte[] input) {
        return IntStream.range(0, input.length).map(i -> input[i]).allMatch(b -> b == CR || b == LF || (b >= 20 && b < 0x7F));
    }

    public static TemplateMatcher.Part getSelectionPart(IResponseInfo responseInfo, int fromIndex) {
        final int bodyOffset = responseInfo.getBodyOffset();
        return (bodyOffset != -1) && (fromIndex < bodyOffset) ? TemplateMatcher.Part.header : TemplateMatcher.Part.body;
    }

    public static Path getNucleiPath(IBurpExtenderCallbacks callbacks) {
        // TODO the OS detection would be enough to happen once at startup
        final String osName = System.getProperty("os.name");
        final String baseBinaryName = "nuclei";
        final String nucleiBinaryName = osName.toLowerCase().startsWith("windows") ? baseBinaryName + ".exe" : baseBinaryName;

        final Path nucleiBinaryPath;
        final String nucleiBinaryPathSetting = callbacks.loadExtensionSetting(SettingsPanel.NUCLEI_PATH_VARIABLE);
        if (nucleiBinaryPathSetting == null || nucleiBinaryPathSetting.trim().equals("")) {
            nucleiBinaryPath = Paths.get(nucleiBinaryName);
        } else {
            nucleiBinaryPath = nucleiBinaryPathSetting.endsWith(nucleiBinaryName) ? Paths.get(nucleiBinaryPathSetting)
                                                                                  : Paths.get(nucleiBinaryPathSetting).resolve(nucleiBinaryName);
        }
        return nucleiBinaryPath;
    }

    public static TemplateMatcher createContentMatcher(byte[] responseBytes, IResponseInfo responseInfo, int[] selectionBounds, IExtensionHelpers helpers) {
        final int fromIndex = selectionBounds[0];
        final int toIndex = selectionBounds[1];

        final byte[] selectedBytes = Arrays.copyOfRange(responseBytes, fromIndex, toIndex);
        final TemplateMatcher.Part selectionPart = Utils.getSelectionPart(responseInfo, fromIndex);

        final TemplateMatcher contentMatcher;
        if (Utils.isAsciiPrintableNewLine(selectedBytes)) {
            contentMatcher = createWordMatcher(selectionPart, helpers.bytesToString(selectedBytes));
        } else {
            final Binary binaryMatcher = new Binary(selectedBytes);
            binaryMatcher.setPart(selectionPart);
            contentMatcher = binaryMatcher;
        }

        return contentMatcher;
    }

    public static TransformedRequest transformRequestWithPayloads(Requests.AttackType attackType, String request) {
        final Matcher matcher = INTRUDER_PAYLOAD_PATTERN.matcher(request);

        return attackType == Requests.AttackType.batteringram ? handleBatteringRam(attackType, request, matcher)
                                                              : handleMultiPayloadAttackTypes(attackType, request, matcher);
    }

    private static TransformedRequest handleMultiPayloadAttackTypes(Requests.AttackType attackType, String request, Matcher matcher) {
        final Map<String, List<String>> payloadParameters = new LinkedHashMap<>();

        final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
            final String indexedParameterName = BASE_PAYLOAD_PARAMETER_NAME + index;
            payloadParameters.put(indexedParameterName, new ArrayList<>(List.of(payloadParameter)));
            return indexedParameterName;
        };

        final String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
        return new TransformedRequest(attackType, transformedRequest, payloadParameters);
    }

    private static TransformedRequest handleBatteringRam(Requests.AttackType attackType, String request, Matcher matcher) {
        final List<String> payloadParameters = new ArrayList<>();
        final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
            payloadParameters.add(payloadParameter);
            return BASE_PAYLOAD_PARAMETER_NAME;
        };

        final String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
        return new TransformedRequest(attackType, transformedRequest, Map.of(BASE_PAYLOAD_PARAMETER_NAME, payloadParameters));
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

    private static TemplateMatcher createWordMatcher(TemplateMatcher.Part selectionPart, String selectedString) {
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

    private static String toSnakeCase(String input) {
        return input.replaceAll("([a-z]+)([A-Z]+)", "$1-$2").toLowerCase();
    }

    private static String createGetterMethodName(String fieldName) {
        return createGetterOrSetterMethodName("get", fieldName);
    }

    private static String createSetterMethodName(String fieldName) {
        return createGetterOrSetterMethodName("set", fieldName);
    }
}
