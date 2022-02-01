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

@SuppressWarnings("unused")
@YamlPropertyOrder({"name", "author", "severity", "description", "reference", "classification", "tags"})
public class Info {

    @YamlProperty
    public enum Severity {
        info, low, medium, high, critical
    }

    @YamlPropertyOrder({"cvss-metrics", "cvss-score", "cve-id", "cwe-id"})
    public static class Classification {
        @YamlProperty("cvss-metrics")
        private final String cvssMetrics = "CVSS:3.0/";
        @YamlProperty("cvss-score")
        private final double cvssScore = 1.0;
        @YamlProperty("cve-id")
        private final String cveId = "CVE-";
        @YamlProperty("cwe-id")
        private final String cweId = "CWE-";
    }

    @YamlProperty
    private String name;
    @YamlProperty
    private String author;
    @YamlProperty
    private Severity severity = Severity.info;

    @YamlProperty
    private final String reference = "https://";
    @YamlProperty
    private final String tags = "tags";
    @YamlProperty
    private final Classification classification = new Classification();
    @YamlProperty
    private final String description = "description";

    public Info() {
    }

    public Info(String name, String author, Severity severity) {
        this.name = name;
        this.author = author;
        this.severity = severity;
    }
}
