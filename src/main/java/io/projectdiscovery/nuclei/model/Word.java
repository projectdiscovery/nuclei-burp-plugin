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
import java.util.Optional;

@SuppressWarnings("unused")
@YamlPropertyOrder({"type", "negative", "part", "condition", "words"})
public class Word implements TemplateMatcher {

    @YamlProperty
    private final String type = Word.class.getSimpleName().toLowerCase();

    @YamlProperty
    private final Boolean negative = false;

    @YamlProperty
    private Part part = Part.all;

    @YamlProperty
    private List<String> words;

    @YamlProperty
    private Condition condition;

    public Word() {
    }

    public Word(String... words) {
        this.words = Arrays.asList(words);
    }

    public List<String> getWords() {
        return this.words;
    }

    @Override
    public String getType() {
        return this.type;
    }

    @Override
    public Part getPart() {
        return this.part;
    }

    @Override
    public void setPart(Part part) {
        this.part = part;
    }

    @Override
    public Condition getCondition() {
        return Optional.ofNullable(this.condition).orElse(Condition.or);
    }

    @Override
    public void setCondition(Condition condition) {
        this.condition = condition;
    }
}