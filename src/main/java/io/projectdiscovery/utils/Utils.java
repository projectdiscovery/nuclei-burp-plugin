/*
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package io.projectdiscovery.utils;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class Utils {

    public static final char CR = '\r';
    public static final char LF = '\n';
    public static final String CRLF = "" + CR + LF;

    private Utils() {
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

    public static boolean isAsciiPrintableNewLine(byte[] input) {
        return IntStream.range(0, input.length).map(i -> input[i]).allMatch(b -> b == CR || b == LF || (b >= 20 && b < 0x7F));
    }

    public static String getOsDependentBinaryName(String baseBinaryName) {
        final String osName = System.getProperty("os.name");
        return osName.toLowerCase().startsWith("windows") ? baseBinaryName + ".exe" : baseBinaryName;
    }

    public static Optional<Path> calculateBinaryOnPath(String binaryName) {
        return Stream.of(System.getenv("PATH").split(Pattern.quote(File.pathSeparator)))
                     .map(Paths::get)
                     .map(path -> path.resolve(binaryName))
                     .filter(Files::exists)
                     .findFirst();
    }

    public static Path getTempPath() {
        return Paths.get(System.getProperty("java.io.tmpdir"));
    }

    public static <T extends Enum<T>> List<String> getEnumValues(Class<T> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants()).map(Enum::name).collect(Collectors.toList());
    }

    @SafeVarargs
    public static <T> List<T> createNewList(Collection<T> collection, T... elements) {
        return collection == null ? Arrays.asList(elements) : Stream.concat(Stream.of(elements), collection.stream())
                                                                    .collect(Collectors.toList());
    }
}
