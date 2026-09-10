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

package io.projectdiscovery.cve.nist.service;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import io.projectdiscovery.cve.CveInfo;
import io.projectdiscovery.cve.nist.NistCveInfo;
import io.projectdiscovery.cve.nist.model.Cve;
import io.projectdiscovery.cve.nist.model.NvdCveResponse;
import io.projectdiscovery.cve.nist.model.Vulnerability;
import io.projectdiscovery.nuclei.gui.GeneralSettings;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

public final class CveInfoRetriever {

    private static final Gson GSON = new Gson();
    private static final String NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private CveInfoRetriever() {
    }

    public static Optional<CveInfo> getCveInfo(String cveId, GeneralSettings generalSettings) {
        final Optional<NistCveInfo> cveInfo = retrieveCve(cveId, generalSettings).map(NistCveInfo::new);

        cveInfo.filter(cve -> !cve.hasCvssV3Score())
               .ifPresent(cve -> generalSettings.log(String.format("The NVD has no CVSS v3 score for '%s', so the severity and score need to be filled in manually.", cveId)));

        return cveInfo.map(CveInfo.class::cast);
    }

    private static Optional<Cve> retrieveCve(String cveId, GeneralSettings generalSettings) {
        return sendRequest(cveId, generalSettings).map(NvdCveResponse::getVulnerabilities)
                                                  .filter(vulnerabilities -> vulnerabilities != null && !vulnerabilities.isEmpty())
                                                  .map(vulnerabilities -> vulnerabilities.get(0))
                                                  .map(Vulnerability::getCve)
                                                  .filter(cve -> cveId.equalsIgnoreCase(cve.getId()));
    }

    private static Optional<NvdCveResponse> sendRequest(String cveId, GeneralSettings generalSettings) {
        // The API matches the id case sensitively and answers 404 for a lower case one.
        final String normalizedCveId = cveId.toUpperCase(Locale.ROOT);
        final URI uri = URI.create(String.format("%s?cveId=%s", NVD_CVE_API_URL, URLEncoder.encode(normalizedCveId, StandardCharsets.UTF_8)));

        try {
            final HttpRequest httpRequest = HttpRequest.newBuilder(uri)
                                                       .timeout(TIMEOUT)
                                                       .GET()
                                                       .build();

            final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
            final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            final int statusCode = httpResponse.statusCode();
            if (statusCode != 200) {
                // The NVD throttles clients without an API key to a few requests per 30 second window.
                final String hint = (statusCode == 403 || statusCode == 429) ? " Clients without an API key are rate limited, so retrying in a few seconds may work." : "";
                generalSettings.logError(String.format("The NVD API returned HTTP %d for '%s'.%s", statusCode, normalizedCveId, hint));
                return Optional.empty();
            }

            return Optional.ofNullable(GSON.fromJson(httpResponse.body(), NvdCveResponse.class));
        } catch (JsonParseException e) {
            generalSettings.logError(String.format("Could not parse the NVD API response for '%s'.", cveId), e);
        } catch (IOException e) {
            generalSettings.logError(String.format("Could not reach the NVD API at '%s'.", uri), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            generalSettings.logError(String.format("Interrupted while retrieving '%s' from the NVD API.", cveId), e);
        }

        return Optional.empty();
    }
}
