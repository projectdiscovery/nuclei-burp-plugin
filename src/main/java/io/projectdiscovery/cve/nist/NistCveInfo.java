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

import io.projectdiscovery.cve.CveInfo;
import io.projectdiscovery.cve.nist.model.CVE;
import io.projectdiscovery.cve.nist.model.CveItem;
import io.projectdiscovery.cve.nist.model.cwe.ProblemTypeDescription;
import io.projectdiscovery.cve.nist.model.description.DescriptionData;
import io.projectdiscovery.cve.nist.model.impact.CvssV3;
import io.projectdiscovery.cve.nist.model.references.ReferenceData;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import java.util.stream.Collectors;

public class NistCveInfo implements CveInfo {

    private final String description;
    private final Set<String> cwes;
    private final Set<String> references;
    private final CvssV3 cvss;
    private final String id;

    public NistCveInfo(CveItem cveItem) {
        final CVE cve = cveItem.getCve();

        this.id = cve.getCveMetaData().getId();

        this.description = cve.getDescription().getDescriptionData().stream()
                              .findAny()
                              .map(DescriptionData::getValue)
                              .orElse(null);

        this.cwes = cve.getProblemType().getProblemTypeData().stream()
                       .flatMap(r -> r.getDescription().stream())
                       .map(ProblemTypeDescription::getValue)
                       .filter(v -> v.toLowerCase().startsWith("cwe-"))
                       .collect(Collectors.toSet());

        this.references = cve.getReferences().getReferenceData().stream()
                             .map(ReferenceData::getUrl)
                             .filter(r -> {
                                 try {
                                     new URL(r);
                                     return true;
                                 } catch (MalformedURLException e) {
                                     return false;
                                 }
                             })
                             .collect(Collectors.toSet());

        this.cvss = cveItem.getImpact().getBaseMetricV3().getCvssV3();
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public Double getCvssScore() {
        return this.cvss.getBaseScore();
    }

    @Override
    public String getCvssMetrics() {
        return this.cvss.getVectorString();
    }

    @Override
    public String getSeverity() {
        return this.cvss.getBaseSeverity();
    }

    @Override
    public Set<String> getCweIds() {
        return this.cwes;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public Set<String> getReferences() {
        return this.references;
    }
}
