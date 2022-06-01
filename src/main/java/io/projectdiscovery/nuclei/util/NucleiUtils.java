package io.projectdiscovery.nuclei.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.projectdiscovery.nuclei.model.TemplateMatcher;
import io.projectdiscovery.utils.Utils;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class NucleiUtils {

    public static final String NUCLEI_BASE_BINARY_NAME = "nuclei";

    private static final Pattern NUCLEI_TEMPLATE_PARAMETER_PATTERN = Pattern.compile("(-t)\\s+(\"[^\"]+\"|'[^']+'|[^ ]+)");
    private static final Pattern HELP_LINE_REGEX = Pattern.compile("(?:\t| {3})(-[a-z-]+)(?:, (-[a-z-]+))?(?: [a-z-\\[\\]]+)?\\s+(.*)");

    private NucleiUtils() {
    }

    public static TemplateMatcher.Part getSelectionPart(int bodyOffset, int fromIndex) {
        return (bodyOffset != -1) && (fromIndex < bodyOffset) ? TemplateMatcher.Part.header : TemplateMatcher.Part.body;
    }

    public static String getNucleiBinaryName() {
        return Utils.getOsDependentBinaryName(NUCLEI_BASE_BINARY_NAME);
    }

    public static Optional<Path> calculateNucleiPath() {
        return Utils.calculateBinaryOnPath(getNucleiBinaryName());
    }

    public static Path getConfiguredNucleiPath(Optional<Path> nucleiBinaryPathSetting, String nucleiBinaryName) {
        return nucleiBinaryPathSetting.map(path -> path.endsWith(nucleiBinaryName) ? path
                                                                                   : path.resolve(nucleiBinaryName))
                                      .orElseGet(() -> Paths.get(nucleiBinaryName));
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

    public static Map<String, String> getCliArguments(BufferedReader bufferedReader) {
        return getCliArguments(bufferedReader.lines());
    }

    public static Map<String, String> getCliArguments(Stream<String> nucleiHelpStream) {
        return nucleiHelpStream.filter(line -> line.startsWith("   -"))
                               .map(NucleiUtils::createCliArgument)
                               .filter(Objects::nonNull)
                               .collect(Collectors.toMap(CliArgument::toString,
                                                         CliArgument::getShortName,
                                                         (a, b) -> a,
                                                         LinkedHashMap::new));
    }

    @Nullable
    private static CliArgument createCliArgument(String line) {
        final Matcher matcher = HELP_LINE_REGEX.matcher(line);
        return matcher.matches() ? matcher.groupCount() == 3 ? new CliArgument(matcher.group(1), matcher.group(2), matcher.group(3))
                                                             : new CliArgument(matcher.group(1), matcher.group(2))
                                 : null;
    }
}
