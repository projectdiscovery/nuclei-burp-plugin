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

import java.util.Arrays;
import java.util.List;

@SuppressWarnings("unused")
@YamlPropertyOrder({"type", "part", "status"})
public class Status implements TemplateMatcher {

    @YamlProperty
    public String type = Status.class.getSimpleName().toLowerCase();

    @YamlProperty
    public List<Integer> status;

    public Status() {
    }

    public Status(Integer... status) {
        this.status = Arrays.asList(status);
    }

    public List<Integer> getStatus() {
        return this.status;
    }

    @Override
    public String getType() {
        return this.type;
    }

    @Override
    public Part getPart() {
        return null; // the part is ignored by the status matcher
    }

    @Override
    public void setPart(Part part) {
        // do nothing
    }
}
