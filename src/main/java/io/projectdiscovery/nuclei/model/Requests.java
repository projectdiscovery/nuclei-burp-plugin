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

import java.util.List;

@SuppressWarnings("unused")
public class Requests {

    public enum MatchersCondition {
        and, or
    }

    private MatchersCondition matchersCondition = MatchersCondition.and;
    private List<String> raw;
    private List<Matcher> matchers;

    public List<String> getRaw() {
        return raw;
    }

    public void setRaw(List<String> raw) {
        this.raw = raw;
    }

    public void setRaw(String... raw) {
        this.raw = List.of(raw);
    }

    public List<Matcher> getMatchers() {
        return matchers;
    }

    public void setMatchers(List<Matcher> matchers) {
        this.matchers = matchers;
    }

    public void setMatchers(Matcher... matchers) {
        this.matchers = List.of(matchers);
    }

    public void setMatchersCondition(MatchersCondition matchersCondition) {
        this.matchersCondition = matchersCondition;
    }

    public MatchersCondition getMatchersCondition() {
        return matchersCondition;
    }
}
