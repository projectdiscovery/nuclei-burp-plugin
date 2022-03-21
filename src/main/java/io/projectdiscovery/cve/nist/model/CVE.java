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

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.projectdiscovery.cve.nist.model.cwe.ProblemType;
import io.projectdiscovery.cve.nist.model.description.Description;
import io.projectdiscovery.cve.nist.model.references.References;

public class CVE {

    @SerializedName("CVE_data_meta")
    private CveMetaData cveMetaData;

    @Expose
    private References references;

    @Expose
    private Description description;

    @SerializedName("problemtype")
    private ProblemType problemType;

    public References getReferences() {
        return this.references;
    }

    public Description getDescription() {
        return this.description;
    }

    public ProblemType getProblemType() {
        return this.problemType;
    }

    public CveMetaData getCveMetaData() {
        return this.cveMetaData;
    }
}
