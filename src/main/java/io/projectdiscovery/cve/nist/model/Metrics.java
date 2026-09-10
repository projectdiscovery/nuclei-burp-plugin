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

package io.projectdiscovery.cve.nist.model;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public class Metrics {

    private List<CvssMetric> cvssMetricV31;
    private List<CvssMetric> cvssMetricV30;

    /**
     * @return the CVSS v3 data, preferring v3.1 over v3.0. Empty for CVEs that the NVD only scored with CVSS v2.
     */
    public Optional<CvssData> getCvssV3Data() {
        return Stream.of(this.cvssMetricV31, this.cvssMetricV30)
                     .filter(metrics -> metrics != null && !metrics.isEmpty())
                     .findFirst()
                     .map(metrics -> metrics.get(0).getCvssData());
    }
}
