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
import io.projectdiscovery.cve.CveInfo;
import io.projectdiscovery.cve.nist.NistCveInfo;
import io.projectdiscovery.cve.nist.model.CveMetaData;
import io.projectdiscovery.cve.nist.model.NistCveResults;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

public final class CveInfoRetriever {

    private static final Gson GSON = new Gson();
    private static final String NIST_SERVICE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/";

    private CveInfoRetriever() {
    }

    public static Optional<CveInfo> getCveInfo(String cveId) {
        try {
            return getNistCveResults(cveId).filter(cveInfo -> cveInfo.getTotalResults() == 1)
                                           .map(cveInfo -> cveInfo.getResults().getCveItems().get(0))
                                           .filter(cveInfo -> {
                                               final CveMetaData cveMetaData = cveInfo.getCve().getCveMetaData();
                                               final String id = cveMetaData.getId();
                                               return cveId.equalsIgnoreCase(id);
                                           })
                                           .map(NistCveInfo::new);
        } catch (NullPointerException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            return Optional.empty();
        }
    }

    private static Optional<NistCveResults> getNistCveResults(String cveId) {
        try {
            final HttpRequest httpRequest = HttpRequest.newBuilder(new URI(NIST_SERVICE_URL).resolve(cveId))
                                                       .GET()
                                                       .build();

            final HttpClient httpClient = HttpClient.newHttpClient();
            final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return Optional.of(GSON.fromJson(httpResponse.body(), NistCveResults.class));
        } catch (URISyntaxException | IOException | InterruptedException e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }
}