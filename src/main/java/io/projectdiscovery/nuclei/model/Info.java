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

package io.projectdiscovery.nuclei.model;

import io.projectdiscovery.nuclei.model.util.YamlProperty;
import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;

import java.util.*;

@SuppressWarnings("unused")
@YamlPropertyOrder({"name", "author", "severity", "description", "reference", "classification", "tags"})
public class Info {

    private static final String DEFAULT_REFERENCE = "https://";
    private static final String DEFAULT_DESCRIPTION = "description";
    private static final String DEFAULT_TAGS = "tags";

    public enum Severity {
        info, low, medium, high, critical, unknown;

        public static Severity of(String value) {
            return Arrays.stream(values())
                         .filter(severity -> severity.toString().equals(value.toLowerCase()))
                         .findAny()
                         .orElse(unknown);
        }
    }

    @YamlPropertyOrder({"cvss-metrics", "cvss-score", "cve-id", "cwe-id"})
    public static class Classification {
        @YamlProperty("cvss-metrics")
        private final String cvssMetrics;
        @YamlProperty("cvss-score")
        private final double cvssScore;
        @YamlProperty("cve-id")
        private final String cveId;
        @YamlProperty("cwe-id")
        private final String cweId;

        public Classification(String cveId, String cvssMetrics, double cvssScore, Set<String> cweIds) {
            this(cveId, cvssMetrics, cvssScore, cweIds.isEmpty() ? null : String.join(", ", cweIds));
        }

        public Classification(String cveId, String cvssMetrics, double cvssScore, String cweId) {
            this.cveId = cveId;
            this.cvssMetrics = cvssMetrics;
            this.cvssScore = cvssScore;
            this.cweId = cweId;
        }

        public Classification() {
            this.cveId = "CVE-";
            this.cvssMetrics = "CVSS:3.0/";
            this.cvssScore = 1.0;
            this.cweId = "CWE-";
        }
    }

    @YamlProperty
    private String name;
    @YamlProperty
    private String author;
    @YamlProperty
    private Severity severity = Severity.unknown;

    @YamlProperty
    private List<String> reference = new ArrayList<>(List.of(DEFAULT_REFERENCE));
    @YamlProperty
    private String tags = DEFAULT_TAGS;
    @YamlProperty
    private Classification classification;
    @YamlProperty
    private String description = DEFAULT_DESCRIPTION;

    public Info() {
    }

    public Info(String name, String author, Severity severity) {
        this.name = name;
        this.author = author;
        this.severity = severity;
    }

    public String getName() {
        return this.name;
    }

    public String getAuthor() {
        return this.author;
    }

    public Severity getSeverity() {
        return this.severity;
    }

    public void setSeverity(String severity) {
        this.severity = Severity.of(severity);
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public Collection<String> getReference() {
        return this.reference;
    }

    public void setReference(Collection<String> reference) {
        if (this.reference.size() == 1 && this.reference.iterator().next().equals(DEFAULT_REFERENCE)) {
            this.reference = new ArrayList<>(reference);
        } else {
            this.reference.addAll(reference);
            this.reference = new ArrayList<>(new LinkedHashSet<>(this.reference)); // remove potential duplicate elements, but enforce list type
        }
    }

    public String getTags() {
        return this.tags;
    }

    public void setTags(Collection<String> tags) {
        final String[] currentTags = this.tags.split(",");

        final Collection<String> newTags;
        if (currentTags.length == 1 && currentTags[0].equals(DEFAULT_TAGS)) {
            newTags = tags;
        } else {
            newTags = new LinkedHashSet<>(Arrays.asList(currentTags));
            newTags.addAll(tags);
        }
        this.tags = String.join(",", newTags);
    }

    public Classification getClassification() {
        return this.classification;
    }

    public void setClassification(Classification classification) {
        this.classification = classification;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setDescriptionIfDefault(String description) {
        if (this.description.equals(DEFAULT_DESCRIPTION)) {
            this.description = description;
        }
    }
}
