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

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SuppressWarnings("unused")
public class Requests {

    public enum MatchersCondition {
        and, or
    }

    public enum AttackTypes {
        batteringram, pitchfork, clusterbomb
    }

    private MatchersCondition matchersCondition = MatchersCondition.and;
    private List<String> raw;
    private AttackTypes attack;
    private Map<String, List<String>> payloads;
    private List<Matcher> matchers;

    public List<String> getRaw() {
        return raw;
    }

    public void setRaw(List<String> raw) {
        this.raw = normalizeRawRequest(raw.stream());
    }

    public void setRaw(String... raw) {
        this.raw = normalizeRawRequest(Arrays.stream(raw));
    }

    public void setRaw(byte[]... raw) {
        // needed otherwise the dumped raw request will be shown in-line, between double quotes
        this.raw = normalizeRawRequest(Arrays.stream(raw).map(String::new));
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

    private List<String> normalizeRawRequest(Stream<String> content) {
        return content.map(s -> s.replaceAll("\r", "")).collect(Collectors.toList());
    }

    public void setAttack(AttackTypes attack) {
        this.attack = attack;
    }

    public AttackTypes getAttack() {
        return attack;
    }

    public Map<String, List<String>> getPayloads() {
        return payloads;
    }

    public void setPayloads(Map<String, List<String>> payloads) {
        if (Objects.isNull(attack)) {
            attack = AttackTypes.batteringram;
        }
        this.payloads = payloads;
    }

    public void addPayloads(String key, String... payloads) {
        if (Objects.nonNull(payloads)) {
            if (Objects.isNull(this.payloads)) {
                setPayloads(new LinkedHashMap<>(Map.of(key, List.of(payloads))));
            } else {
                this.payloads.merge(key, List.of(payloads), (v1, v2) -> {
                    v1.addAll(v2);
                    return v1;
                });
            }
        }
    }
}
