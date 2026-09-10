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
import io.projectdiscovery.cve.nist.model.Cve;
import io.projectdiscovery.cve.nist.model.CvssData;
import io.projectdiscovery.cve.nist.model.LangValue;
import io.projectdiscovery.cve.nist.model.Metrics;
import io.projectdiscovery.cve.nist.model.Reference;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class NistCveInfo implements CveInfo {

    private static final String ENGLISH = "en";
    private static final String UNKNOWN_SEVERITY = "unknown";
    private static final String CWE_PREFIX = "cwe-";

    private final String id;
    private final String description;
    private final Set<String> cweIds;
    private final Set<String> references;
    private final CvssData cvssData;

    public NistCveInfo(Cve cve) {
        this.id = cve.getId();
        this.description = englishValues(cve.getDescriptions()).findFirst().orElse(null);

        this.cweIds = nullSafe(cve.getWeaknesses()).stream()
                                                   .flatMap(weakness -> englishValues(weakness.getDescription()))
                                                   .filter(value -> value.toLowerCase().startsWith(CWE_PREFIX))
                                                   .collect(Collectors.toCollection(LinkedHashSet::new));

        this.references = nullSafe(cve.getReferences()).stream()
                                                       .map(Reference::getUrl)
                                                       .filter(NistCveInfo::isValidUrl)
                                                       .collect(Collectors.toCollection(LinkedHashSet::new));

        this.cvssData = Optional.ofNullable(cve.getMetrics())
                                .flatMap(Metrics::getCvssV3Data)
                                .orElse(null);
    }

    /**
     * @return whether the NVD scored this CVE with CVSS v3, which is not the case for some older entries
     */
    public boolean hasCvssV3Score() {
        return this.cvssData != null;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public Double getCvssScore() {
        // Info.Classification stores the score as a primitive, so absent scores fall back to zero.
        return hasCvssV3Score() ? this.cvssData.getBaseScore() : 0.0;
    }

    @Override
    public String getCvssMetrics() {
        return hasCvssV3Score() ? this.cvssData.getVectorString() : null;
    }

    @Override
    public String getSeverity() {
        return hasCvssV3Score() ? this.cvssData.getBaseSeverity() : UNKNOWN_SEVERITY;
    }

    @Override
    public Set<String> getCweIds() {
        return this.cweIds;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public Set<String> getReferences() {
        return this.references;
    }

    private static Stream<String> englishValues(List<LangValue> langValues) {
        return nullSafe(langValues).stream()
                                   .filter(langValue -> ENGLISH.equalsIgnoreCase(langValue.getLang()))
                                   .map(LangValue::getValue)
                                   .filter(Objects::nonNull);
    }

    private static boolean isValidUrl(String url) {
        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private static <T> Collection<T> nullSafe(List<T> values) {
        return values == null ? Collections.emptyList() : values;
    }
}
