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

@SuppressWarnings({"unused", "FieldCanBeLocal"})
@YamlPropertyOrder({"id", "info", "requests"})
public class Template {

    @YamlProperty
    private String id;
    @YamlProperty
    private Info info;
    @YamlProperty
    private List<Requests> requests;

    public Template() {
    }

    public Template(String id, Info info, Requests... requests) {
        this.id = id;
        this.info = info;
        this.requests = Arrays.asList(requests);
    }
}
