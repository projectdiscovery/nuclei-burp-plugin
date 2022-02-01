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

import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.model.util.YamlProperty;
import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@YamlPropertyOrder({"raw", "attack", "payloads", "matchers-condition", "matchers"})
public class Requests {

    @YamlProperty("matchers-condition")
    public enum MatchersCondition {
        and, or
    }

    @YamlProperty
    public enum AttackType {
        batteringram, pitchfork, clusterbomb
    }

    @YamlProperty
    private MatchersCondition matchersCondition;
    @YamlProperty
    private List<String> raw;
    @YamlProperty
    private AttackType attack;
    @YamlProperty
    private Map<String, List<String>> payloads;
    @YamlProperty
    private List<TemplateMatcher> matchers;

    public List<String> getRaw() {
        return this.raw;
    }

    public void setRaw(String... raw) {
        this.raw = normalizeRawRequest(Arrays.stream(raw));
    }

    public void setRaw(byte[]... raw) {
        // needed otherwise the dumped raw request will be shown in-line, between double quotes
        this.raw = normalizeRawRequest(Arrays.stream(raw).map(String::new));
    }

    public List<TemplateMatcher> getMatchers() {
        return this.matchers;
    }

    /**
     * For requests with payloads, use {@link #setTransformedRequest} instead
     */
    public void setMatchers(TemplateMatcher... matchers) {
        this.matchers = List.of(matchers);

        if (Objects.isNull(this.matchersCondition) && this.matchers.size() > 1) {
            this.matchersCondition = MatchersCondition.and;
        }
    }

    public void setMatchersCondition(MatchersCondition matchersCondition) {
        this.matchersCondition = matchersCondition;
    }

    public MatchersCondition getMatchersCondition() {
        return this.matchersCondition;
    }

    public AttackType getAttack() {
        return this.attack;
    }

    public Map<String, List<String>> getPayloads() {
        return this.payloads;
    }

    public void setTransformedRequest(TransformedRequest transformedRequest) {
        this.attack = transformedRequest.getAttackType();
        setRaw(transformedRequest.getRequest());
        this.payloads = transformedRequest.getParameters();
    }

    public void addPayloads(AttackType attackType, String key, String... payloads) {
        if (this.attack == null) {
            this.attack = attackType;
        } else if (this.attack != attackType) {
            throw new IllegalArgumentException("An attack type with an associated raw request was already set.");
        }

        if (payloads != null) {
            if (attackType == AttackType.batteringram) {
                this.payloads.values().stream().findFirst().ifPresentOrElse(v -> v.addAll(Arrays.asList(payloads)), () -> addPayloads(key, payloads));
            } else {
                addPayloads(key, payloads);
            }
        }
    }

    private void addPayloads(String key, String... payloads) {
        if (this.payloads == null) {
            this.payloads = new LinkedHashMap<>(Map.of(key, new ArrayList<>(List.of(payloads))));
        } else {
            this.payloads.merge(key, List.of(payloads), (v1, v2) -> {
                v1.addAll(v2);
                return v1;
            });
        }
    }

    private List<String> normalizeRawRequest(Stream<String> content) {
        return content.map(s -> s.replaceAll("\r", "")).collect(Collectors.toList());
    }
}
