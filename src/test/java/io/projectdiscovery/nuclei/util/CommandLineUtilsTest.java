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

package io.projectdiscovery.nuclei.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

class CommandLineUtilsTest {

    @Test
    void testCommandSplitToChunks() {
        final Map<String, String[]> testCases = Map.of(
                "nuclei -t ~/nuclei-templates/my-template.yaml -u http://localhost:8080", new String[]{"nuclei", "-t", "~/nuclei-templates/my-template.yaml", "-u", "http://localhost:8080"},
                "nuclei -t \"/tmp/dir space/template.yaml\" -u \"/users/directory with space/\"", new String[]{"nuclei", "-t", "/tmp/dir space/template.yaml", "-u", "/users/directory with space/"},
                "\"c:/program files/nuclei.exe\" -t \"template.yaml\" -u \"c:/users/directory with space/\" -nc", new String[]{"c:/program files/nuclei.exe", "-t", "template.yaml", "-u", "c:/users/directory with space/", "-nc"}
        );

        testCases.forEach((key, value) -> Assertions.assertArrayEquals(value, CommandLineUtils.stringCommandToChunks(key)));
    }
}