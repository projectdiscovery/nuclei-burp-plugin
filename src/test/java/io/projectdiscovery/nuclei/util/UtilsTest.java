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
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

class UtilsTest {

    @Test
    void testCommandSplitToChunks() {
        final Map<String, String[]> testCases = Map.of(
                "nuclei -t ~/nuclei-templates/my-template.yaml -u http://localhost:8080", new String[]{"nuclei", "-t", "~/nuclei-templates/my-template.yaml", "-u", "http://localhost:8080"},
                "nuclei -t \"/tmp/dir space/template.yaml\" -u \"/users/directory with space/\"", new String[]{"nuclei", "-t", "/tmp/dir space/template.yaml", "-u", "/users/directory with space/"},
                "\"c:/program files/nuclei.exe\" -t \"template.yaml\" -u \"c:/users/directory with space/\" -nc", new String[]{"c:/program files/nuclei.exe", "-t", "template.yaml", "-u", "c:/users/directory with space/", "-nc"}
        );

        testCases.forEach((key, value) -> Assertions.assertArrayEquals(value, Utils.stringCommandToChunks(key)));
    }

    @Test
    void testSimpleYaml() {
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

    @Test
    void testExtensiveYamlGeneration() {
        final Template template = createExtensiveTemplate();

        final String expected = "id: template-id\n" +
                                "info:\n" +
                                "  author: forgedhallpass\n" +
                                "  name: Template Name\n" +
                                "  severity: info\n" +
                                "requests:\n" +
                                "- matchers-condition: or\n" +
                                "  attack: clusterbomb\n" +
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
                                "  payloads:\n" +
                                "    param1:\n" +
                                "    - headerOne\n" +
                                "    - one\n" +
                                "    param2:\n" +
                                "    - headerTwo\n" +
                                "    - two\n" +
                                "  raw:\n" +
                                "  - |-\n" +
                                "    GET / HTTP/1.1\n" +
                                "    Host: {{Hostname}}\n" +
                                "    Accept: */*\n" +
                                "    HeaderOne: {{param1}}\n" +
                                "    HeaderTwo: {{param2}}\n";

        Assertions.assertEquals(expected, Utils.dumpYaml(template));
    }

    @Test
    void transformRequestWithBatteringRam() {
        final String request = "GET / HTTP/1.1\n" +
                               "Host: localhost\n" +
                               "User-Agent: §Mozilla/5.0§ (Macintosh; Intel Mac OS X 10.15; rv:96.0) Gecko/20100101 Firefox/96.0\n" +
                               "Accept-Language: en-US,en;§q=0.5\n" +
                               "Accept§-Encoding: §gzip, deflate§\n" +
                               "Pragma: no-cache\n" +
                               "Cache-Control: no-cache\n";

        final TransformedRequest transformedRequest = Utils.transformRequestWithPayloads(Requests.AttackType.batteringram, request);
        final Requests requests = new Requests();
        requests.setTransformedRequest(transformedRequest);
        requests.addPayloads(Requests.AttackType.batteringram, "param1", "Chrome");
        requests.addPayloads(Requests.AttackType.batteringram, "param3", "compress");

        final String expected = "attack: batteringram\n" +
                                "payloads:\n" +
                                "  param:\n" +
                                "  - Mozilla/5.0\n" +
                                "  - |-\n" +
                                "    q=0.5\n" +
                                "    Accept\n" +
                                "  - gzip, deflate\n" +
                                "  - Chrome\n" +
                                "  - compress\n" +
                                "raw:\n" +
                                "- |\n" +
                                "  GET / HTTP/1.1\n" +
                                "  Host: localhost\n" +
                                "  User-Agent: {{param}} (Macintosh; Intel Mac OS X 10.15; rv:96.0) Gecko/20100101 Firefox/96.0\n" +
                                "  Accept-Language: en-US,en;{{param}}-Encoding: {{param}}\n" +
                                "  Pragma: no-cache\n" +
                                "  Cache-Control: no-cache\n";

        Assertions.assertEquals(expected, Utils.dumpYaml(requests));
    }

    private Template createTemplate() {
        final Info info = new Info("Template Name", "forgedhallpass", Info.Severity.info);

        final Requests requests = createRequests("GET / HTTP/1.1\n" +
                                                 "Host: {{Hostname}}\n" +
                                                 "Accept: */*");

        return new Template("template-id", info, requests);
    }

    private Template createExtensiveTemplate() {
        final Info info = new Info("Template Name", "forgedhallpass", Info.Severity.info);

        final String rawRequest = "GET / HTTP/1.1\n" +
                                  "Host: {{Hostname}}\n" +
                                  "Accept: */*\n" +
                                  "HeaderOne: §headerOne§\n" +
                                  "HeaderTwo: §headerTwo§";
        final Requests requests = createRequests(rawRequest);

        requests.setTransformedRequest(Utils.transformRequestWithPayloads(Requests.AttackType.clusterbomb, rawRequest));
        requests.addPayloads(Requests.AttackType.clusterbomb, "param1", "one");
        requests.addPayloads(Requests.AttackType.clusterbomb, "param2", "two");

        requests.setMatchers(new Word("word1", "word2"),
                             new Status(200, 500));

        return new Template("template-id", info, requests);
    }

    private Requests createRequests(String rawRequest) {
        final Requests requests = new Requests();
        requests.setMatchersCondition(Requests.MatchersCondition.or);
        requests.setRaw(rawRequest);

        requests.setMatchers(new Word("word1", "word2"),
                             new Status(200, 500));
        return requests;
    }
}