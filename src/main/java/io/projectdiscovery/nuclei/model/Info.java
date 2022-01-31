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

import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;

@SuppressWarnings("unused")
@YamlPropertyOrder({"name", "author", "severity", "description", "reference", "classification", "tags"})
public class Info {

    public enum Severity {
        info, low, medium, high, critical
    }

    @YamlPropertyOrder({"cvss-metrics", "cvss-score", "cve-id", "cwe-id"})
    public static class Classification {
        private String cvssMetrics = "CVSS:3.0/";
        private double cvssScore = 1.0;
        private String cveId = "CVE-";
        private String cweId = "CWE-";

        public Classification() {
        }

        public String getCvssMetrics() {
            return this.cvssMetrics;
        }

        public void setCvssMetrics(String cvssMetrics) {
            this.cvssMetrics = cvssMetrics;
        }

        public double getCvssScore() {
            return this.cvssScore;
        }

        public void setCvssScore(double cvssScore) {
            this.cvssScore = cvssScore;
        }

        public String getCveId() {
            return this.cveId;
        }

        public void setCveId(String cveId) {
            this.cveId = cveId;
        }

        public String getCweId() {
            return this.cweId;
        }

        public void setCweId(String cweId) {
            this.cweId = cweId;
        }
    }

    private String name;
    private String author;
    private Severity severity = Severity.info;

    private String reference = "https://";
    private String tags = "tags";
    private Classification classification = new Classification();
    private String description = "description";

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

    public void setName(String name) {
        this.name = name;
    }

    public String getAuthor() {
        return this.author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public Severity getSeverity() {
        return this.severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getReference() {
        return this.reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }

    public String getTags() {
        return this.tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
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
}
