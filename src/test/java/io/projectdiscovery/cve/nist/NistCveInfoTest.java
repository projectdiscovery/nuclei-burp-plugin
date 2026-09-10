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

package io.projectdiscovery.cve.nist;

import com.google.gson.Gson;
import io.projectdiscovery.cve.nist.model.NvdCveResponse;
import io.projectdiscovery.cve.nist.model.Vulnerability;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

class NistCveInfoTest {

    @Test
    void testCveWithCvssV3Score() {
        final NistCveInfo cveInfo = load("/nvd/cve-2021-44228.json");

        Assertions.assertEquals("CVE-2021-44228", cveInfo.getId());
        Assertions.assertTrue(cveInfo.hasCvssV3Score());
        Assertions.assertEquals(10.0, cveInfo.getCvssScore());
        Assertions.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cveInfo.getCvssMetrics());
        Assertions.assertEquals("CRITICAL", cveInfo.getSeverity());
        Assertions.assertEquals(Set.of("CWE-20", "CWE-400", "CWE-502", "CWE-917"), cveInfo.getCweIds());
        Assertions.assertEquals(3, cveInfo.getReferences().size());
    }

    @Test
    void testOnlyTheEnglishDescriptionIsUsed() {
        // The fixtures are trimmed NVD responses whose non-English descriptions
        // were replaced with a placeholder.
        final NistCveInfo cveInfo = load("/nvd/cve-2021-44228.json");

        Assertions.assertNotNull(cveInfo.getDescription());
        Assertions.assertTrue(cveInfo.getDescription().startsWith("Apache Log4j2"));
    }

    @Test
    void testCveWithoutCvssV3Score() {
        // The NVD only scored pre-2016 entries like this one with CVSS v2.
        final NistCveInfo cveInfo = load("/nvd/cve-1999-0001.json");

        Assertions.assertEquals("CVE-1999-0001", cveInfo.getId());
        Assertions.assertFalse(cveInfo.hasCvssV3Score());
        Assertions.assertEquals(0.0, cveInfo.getCvssScore());
        Assertions.assertNull(cveInfo.getCvssMetrics());
        Assertions.assertEquals("unknown", cveInfo.getSeverity());
        Assertions.assertEquals(Set.of("CWE-20"), cveInfo.getCweIds());
    }

    private static NistCveInfo load(String resource) {
        try (final InputStream inputStream = NistCveInfoTest.class.getResourceAsStream(resource);
             final InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {

            final NvdCveResponse response = new Gson().fromJson(reader, NvdCveResponse.class);

            Assertions.assertEquals(1, response.getTotalResults());
            final List<Vulnerability> vulnerabilities = response.getVulnerabilities();
            Assertions.assertEquals(1, vulnerabilities.size());

            return new NistCveInfo(vulnerabilities.get(0).getCve());
        } catch (IOException e) {
            throw new AssertionError(String.format("Could not read the '%s' test resource.", resource), e);
        }
    }
}
