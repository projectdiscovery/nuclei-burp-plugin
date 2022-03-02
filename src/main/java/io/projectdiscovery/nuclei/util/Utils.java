package io.projectdiscovery.nuclei.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.projectdiscovery.nuclei.model.Binary;
import io.projectdiscovery.nuclei.model.Requests;
import io.projectdiscovery.nuclei.model.TemplateMatcher;
import io.projectdiscovery.nuclei.model.Word;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;

import java.awt.*;
import java.io.*;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class Utils {

    public static final String NUCLEI_BASE_BINARY_NAME = "nuclei";
    public static final Pattern NUCLEI_TEMPLATE_PARAMETER_PATTERN = Pattern.compile("(-t)\\s+(\"[^\"]+\"|'[^']+'|[^ ]+)");

    public static final String PAYLOAD_START_MARKER = "{{";
    public static final String PAYLOAD_END_MARKER = "}}";

    public static final char INTRUDER_PAYLOAD_MARKER = '§';
    private static final Pattern HELP_LINE_REGEX = Pattern.compile("(?:\t| {3})(-[a-z-]+)(?:, (-[a-z-]+))?(?: [a-z-\\[\\]]+)?\\s+(.*)");
    private static final Pattern INTRUDER_PAYLOAD_PATTERN = Pattern.compile(String.format("(%1$s.*?%1$s)", INTRUDER_PAYLOAD_MARKER), Pattern.DOTALL);

    private static final char CR = '\r';
    private static final char LF = '\n';
    private static final String CRLF = "" + CR + LF;

    private static final String BASE_PAYLOAD_PARAMETER_NAME = "param";

    private Utils() {
    }

    public static void asyncExecuteCommand(String command, Consumer<BufferedReader> processOutputConsumer, Consumer<Integer> exitCodeConsumer, Consumer<String> errorHandler) {
        final String[] commandParts = stringCommandToChunks(command);
        asyncExecuteCommand(commandParts, processOutputConsumer, exitCodeConsumer, errorHandler);
    }

    static String[] stringCommandToChunks(String command) {
        return command.replaceAll("^\"", "")
                      .split("\"?( |$)(?=(([^\"]*\"){2})*[^\"]*$)\"?");
    }

    public static <T> ExecutionResult<T> executeCommand(String[] command, Function<BufferedReader, T> processOutputFunction) throws ExecutionException {
        final ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        try {
            final Process process = processBuilder.start();
            process.getOutputStream().close(); // close the process's input stream, because otherwise it will hang waiting for an input

            final T result;
            try (final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                result = processOutputFunction.apply(bufferedReader);
            }

            return new ExecutionResult<>(process.waitFor(), result);
        } catch (InterruptedException | IOException ex) {
            throw new ExecutionException(ex);
        }
    }

    public static void asyncExecuteCommand(String[] command, Consumer<BufferedReader> processOutputConsumer, Consumer<Integer> exitCodeConsumer, Consumer<String> errorHandler) {
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

    public static boolean isBlank(String input) {
        return input == null || input.trim().equals("");
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

    public static TemplateMatcher.Part getSelectionPart(int bodyOffset, int fromIndex) {
        return (bodyOffset != -1) && (fromIndex < bodyOffset) ? TemplateMatcher.Part.header : TemplateMatcher.Part.body;
    }

    public static String getNucleiBinaryName() {
        final String osName = System.getProperty("os.name");
        return osName.toLowerCase().startsWith("windows") ? NUCLEI_BASE_BINARY_NAME + ".exe" : NUCLEI_BASE_BINARY_NAME;
    }

    public static Optional<Path> calculateNucleiPath() {
        return Stream.of(System.getenv("PATH").split(Pattern.quote(File.pathSeparator)))
                     .map(Paths::get)
                     .map(path -> path.resolve(getNucleiBinaryName()))
                     .filter(Files::exists)
                     .findFirst();
    }

    public static Path getConfiguredNucleiPath(String nucleiBinaryPathSetting, String nucleiBinaryName) {
        final Path nucleiBinaryPath;
        if (isBlank(nucleiBinaryPathSetting)) {
            nucleiBinaryPath = Paths.get(nucleiBinaryName);
        } else {
            nucleiBinaryPath = nucleiBinaryPathSetting.endsWith(nucleiBinaryName) ? Paths.get(nucleiBinaryPathSetting)
                                                                                  : Paths.get(nucleiBinaryPathSetting).resolve(nucleiBinaryName);
        }
        return nucleiBinaryPath;
    }

    public static Optional<String> detectDefaultTemplatePath() throws IOException {
        final String userHome = System.getProperty("user.home");
        if (userHome != null) {
            final Path templatesConfigJsonPath = Paths.get(userHome).resolve(".config").resolve("nuclei").resolve(".templates-config.json");
            if (Files.exists(templatesConfigJsonPath)) {
                final Gson gson = new Gson();
                final Type mapType = new TypeToken<Map<String, String>>() {
                }.getType();
                final Map<String, String> parsedTemplateConfig = gson.fromJson(Files.readString(templatesConfigJsonPath), mapType);
                final String nucleiTemplatesDirectory = parsedTemplateConfig.get("nuclei-templates-directory");
                return Optional.of(nucleiTemplatesDirectory);
            }
        }
        return Optional.empty();
    }

    public static String replaceTemplatePathInCommand(String nucleiCommand, String newTemplatePath) {
        return NUCLEI_TEMPLATE_PARAMETER_PATTERN.matcher(nucleiCommand).replaceFirst("$1 " + newTemplatePath);
    }

    public static String normalizeTemplate(String yamlTemplate) {
        String result = yamlTemplate;

        for (String fieldName : Arrays.asList("info", "requests", "extractors")) {
            result = addNewLineBeforeProperty(result, fieldName);
        }

        result = result.contains("matchers-condition: ") ? addNewLineBeforeProperty(result, "matchers-condition", getEnumValues(Requests.MatchersCondition.class))
                                                         : addNewLineBeforeProperty(result, "matchers");

        result = result.contains("attack: ") ? addNewLineBeforeProperty(result, "attack", getEnumValues(Requests.AttackType.class))
                                             : addNewLineBeforeProperty(result, "payloads");

        return result;
    }

    public static TemplateMatcher createContentMatcher(byte[] responseBytes, int bodyOffset, int[] selectionBounds, Function<byte[], String> byteToStringFunction) {
        final int fromIndex = selectionBounds[0];
        final int toIndex = selectionBounds[1];

        final byte[] selectedBytes = Arrays.copyOfRange(responseBytes, fromIndex, toIndex);
        final TemplateMatcher.Part selectionPart = getSelectionPart(bodyOffset, fromIndex);

        final TemplateMatcher contentMatcher;
        if (Utils.isAsciiPrintableNewLine(selectedBytes)) {
            contentMatcher = createWordMatcher(selectionPart, byteToStringFunction.apply(selectedBytes));
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

    public static Map<String, String> getCliArguments(BufferedReader bufferedReader) {
        return getCliArguments(bufferedReader.lines());
    }

    public static Map<String, String> getCliArguments(Stream<String> nucleiHelpStream) {
        return nucleiHelpStream.filter(line -> line.startsWith("   -"))
                               .map(Utils::createCliArgument)
                               .filter(Objects::nonNull)
                               .collect(Collectors.toMap(CliArgument::toString,
                                                         CliArgument::getShortName,
                                                         (a, b) -> a,
                                                         LinkedHashMap::new));
    }

    private static CliArgument createCliArgument(String line) {
        final Matcher matcher = HELP_LINE_REGEX.matcher(line);
        return matcher.matches() ? matcher.groupCount() == 3 ? new CliArgument(matcher.group(1), matcher.group(2), matcher.group(3))
                                                             : new CliArgument(matcher.group(1), matcher.group(2))
                                 : null;
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
            final String[] words = selectedStringWithNormalizedNewLines.split(String.valueOf(LF));
            wordMatcher = new Word(words);

            if (words.length > 1) {
                wordMatcher.setCondition(TemplateMatcher.Condition.or);
            }
        }
        wordMatcher.setPart(selectionPart);
        return wordMatcher;
    }

    private static String addNewLineBeforeProperty(String input, String propertyName) {
        return addNewLineBeforeProperty(input, propertyName, Collections.emptyList());
    }

    private static String addNewLineBeforeProperty(String input, String propertyName, List<String> values) {
        final String valuesRegexOrExpression = values.isEmpty() ? ""
                                                                : String.format(" (?:%s)", String.join("|", values));

        final Pattern pattern = Pattern.compile(String.format("(^\\s*%s:%s$)", propertyName, valuesRegexOrExpression), Pattern.MULTILINE);
        final Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            final String group = matcher.group(1);
            input = input.replace(group, "\n" + group);
        }

        return input;
    }

    private static <T extends Enum<T>> List<String> getEnumValues(Class<T> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants()).map(Enum::name).collect(Collectors.toList());
    }
}
