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

import io.projectdiscovery.nuclei.model.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class UtilTest {

    @Test
    void testDumpYaml() {
        final Template template = createTemplate();
        final String expected = "id: template-id\n" +
                                "info:\n" +
                                "  author: forgedhallpass\n" +
                                "  name: Template Name\n" +
                                "  severity: info\n" +
                                "requests:\n" +
                                "- matchers-condition: or\n" +
                                "  matchers:\n" +
                                "  - part: all\n" +
                                "    type: word\n" +
                                "    words:\n" +
                                "    - word1\n" +
                                "    - word2\n" +
                                "  - status:\n" +
                                "    - 200\n" +
                                "    - 500\n" +
                                "    type: status\n" +
                                "  raw:\n" +
                                "  - |-\n" +
                                "    GET / HTTP/1.1\n" +
                                "    Host: {{Hostname}}\n" +
                                "    Accept: */*\n";

        Assertions.assertEquals(expected, Utils.dumpYaml(template));
    }

    private Template createTemplate() {
        final Info info = new Info("Template Name", "forgedhallpass", Info.Severity.info);

        final Requests requests = new Requests();
        requests.setMatchersCondition(Requests.MatchersCondition.or);
        requests.setRaw("GET / HTTP/1.1\nHost: {{Hostname}}\nAccept: */*");

        requests.setMatchers(new Word("word1", "word2"),
                             new Status(200, 500));

        return new Template("template-id", info, requests);
    }
}