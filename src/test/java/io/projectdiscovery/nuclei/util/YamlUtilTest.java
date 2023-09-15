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
import io.projectdiscovery.nuclei.yaml.YamlUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class YamlUtilTest {

    @Test
    void testSimpleYaml() {
        final Template template = createTemplate();
        final String expected = "id: template-id\n" +
                                "info:\n" +
                                "  name: Template Name\n" +
                                "  author: forgedhallpass\n" +
                                "  severity: info\n" +
                                "  description: description\n" +
                                "  reference:\n" +
                                "    - https://\n" +
                                "  tags: tags\n" +
                                "http:\n" +
                                "  - raw:\n" +
                                "      - |-\n" +
                                "        GET / HTTP/1.1\n" +
                                "        Host: {{Hostname}}\n" +
                                "        Accept: */*\n" +
                                "    matchers-condition: or\n" +
                                "    matchers:\n" +
                                "      - type: word\n" +
                                "        part: all\n" +
                                "        words:\n" +
                                "          - word1\n" +
                                "          - word2\n" +
                                "      - type: status\n" +
                                "        status:\n" +
                                "          - 200\n" +
                                "          - 500\n";

        Assertions.assertEquals(expected, YamlUtil.dump(template));
    }

    @Test
    void testExtensiveYamlGeneration() {
        final Template template = createExtensiveTemplate();

        final String expected = "id: template-id\n" +
                                "info:\n" +
                                "  name: Template Name\n" +
                                "  author: forgedhallpass\n" +
                                "  severity: info\n" +
                                "  description: description\n" +
                                "  reference:\n" +
                                "    - https://\n" +
                                "  tags: tags\n" +
                                "http:\n" +
                                "  - raw:\n" +
                                "      - |-\n" +
                                "        GET / HTTP/1.1\n" +
                                "        Host: {{Hostname}}\n" +
                                "        Accept: */*\n" +
                                "        HeaderOne: {{param1}}\n" +
                                "        HeaderTwo: {{param2}}\n" +
                                "    attack: clusterbomb\n" +
                                "    payloads:\n" +
                                "      param1:\n" +
                                "        - headerOne\n" +
                                "        - one\n" +
                                "      param2:\n" +
                                "        - headerTwo\n" +
                                "        - two\n" +
                                "    matchers-condition: or\n" +
                                "    matchers:\n" +
                                "      - type: word\n" +
                                "        part: all\n" +
                                "        words:\n" +
                                "          - word1\n" +
                                "          - word2\n" +
                                "      - type: status\n" +
                                "        status:\n" +
                                "          - 200\n" +
                                "          - 500\n";

        Assertions.assertEquals(expected, YamlUtil.dump(template));
    }

    @Test
    void testDeserializeYaml() {
        final String expected = "id: template-id\n" +
                                "\n" +
                                "info:\n" +
                                "  name: Template Name\n" +
                                "  author: forgedhallpass\n" +
                                "  severity: high\n" +
                                "  description: description\n" +
                                "  reference:\n" +
                                "    - https://\n" +
                                "  tags: tags\n" +
                                "\n" +
                                "http:\n" +
                                "  - raw:\n" +
                                "      - |-\n" +
                                "        GET / HTTP/1.1\n" +
                                "        Host: {{Hostname}}\n" +
                                "        Accept: */*\n" +
                                "        HeaderOne: {{param1}}\n" +
                                "        HeaderTwo: {{param2}}\n" +
                                "\n" +
                                "    attack: clusterbomb\n" +
                                "    payloads:\n" +
                                "      param1:\n" +
                                "        - headerOne\n" +
                                "        - one\n" +
                                "      param2:\n" +
                                "        - headerTwo\n" +
                                "        - two\n" +
                                "\n" +
                                "    matchers-condition: or\n" +
                                "    matchers:\n" +
                                "      - type: word\n" +
                                "        part: all\n" +
                                "        condition: and\n" +
                                "        words:\n" +
                                "          - word1\n" +
                                "          - word2\n" +
                                "      - type: status\n" +
                                "        status:\n" +
                                "          - 200\n" +
                                "          - 500\n";

        final Template template = YamlUtil.load(expected, Template.class);
        Assertions.assertEquals(expected, TemplateUtils.normalizeTemplate(YamlUtil.dump(template)));
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

        final TransformedRequest transformedRequest = TemplateUtils.transformRequestWithPayloads(Requests.AttackType.batteringram, request);
        final Requests requests = new Requests();
        requests.setTransformedRequest(transformedRequest);
        requests.addPayloads(Requests.AttackType.batteringram, "param1", "Chrome");
        requests.addPayloads(Requests.AttackType.batteringram, "param3", "compress");

        final String expected = "raw:\n" +
                                "  - |\n" +
                                "    GET / HTTP/1.1\n" +
                                "    Host: {{Hostname}}\n" +
                                "    User-Agent: {{param}} (Macintosh; Intel Mac OS X 10.15; rv:96.0) Gecko/20100101 Firefox/96.0\n" +
                                "    Accept-Language: en-US,en;{{param}}-Encoding: {{param}}\n" +
                                "    Pragma: no-cache\n" +
                                "    Cache-Control: no-cache\n" +
                                "attack: batteringram\n" +
                                "payloads:\n" +
                                "  param:\n" +
                                "    - Mozilla/5.0\n" +
                                "    - |-\n" +
                                "      q=0.5\n" +
                                "      Accept\n" +
                                "    - gzip, deflate\n" +
                                "    - Chrome\n" +
                                "    - compress\n";

        Assertions.assertEquals(expected, YamlUtil.dump(requests));
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

        requests.setTransformedRequest(TemplateUtils.transformRequestWithPayloads(Requests.AttackType.clusterbomb, rawRequest));
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