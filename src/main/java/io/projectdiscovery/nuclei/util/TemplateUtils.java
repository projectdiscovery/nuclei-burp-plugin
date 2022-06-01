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

package io.projectdiscovery.nuclei.util;

import io.projectdiscovery.nuclei.model.Binary;
import io.projectdiscovery.nuclei.model.Requests;
import io.projectdiscovery.nuclei.model.TemplateMatcher;
import io.projectdiscovery.nuclei.model.Word;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.utils.Utils;

import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TemplateUtils {

    public static final char INTRUDER_PAYLOAD_MARKER = '§';

    public static final String PAYLOAD_START_MARKER = "{{";
    public static final String PAYLOAD_END_MARKER = "}}";

    private static final Pattern INTRUDER_PAYLOAD_PATTERN = Pattern.compile(String.format("(%1$s.*?%1$s)", INTRUDER_PAYLOAD_MARKER), Pattern.DOTALL);

    private static final String BASE_PAYLOAD_PARAMETER_NAME = "param";

    private TemplateUtils() {
    }

    public static String normalizeTemplate(String yamlTemplate) {
        String result = yamlTemplate;

        for (String fieldName : Arrays.asList("info", "requests", "extractors")) {
            result = addNewLineBeforeProperty(result, fieldName);
        }

        result = result.contains("matchers-condition: ") ? addNewLineBeforeProperty(result, "matchers-condition", Utils.getEnumValues(Requests.MatchersCondition.class))
                                                         : addNewLineBeforeProperty(result, "matchers");

        result = result.contains("attack: ") ? addNewLineBeforeProperty(result, "attack", Utils.getEnumValues(Requests.AttackType.class))
                                             : addNewLineBeforeProperty(result, "payloads");

        return result;
    }

    public static TemplateMatcher createContentMatcher(byte[] responseBytes, int bodyOffset, int[] selectionBounds, Function<byte[], String> byteToStringFunction) {
        final int fromIndex = selectionBounds[0];
        final int toIndex = selectionBounds[1];

        final byte[] selectedBytes = Arrays.copyOfRange(responseBytes, fromIndex, toIndex);
        final TemplateMatcher.Part selectionPart = NucleiUtils.getSelectionPart(bodyOffset, fromIndex);

        final TemplateMatcher contentMatcher;
        if (Utils.isAsciiPrintableNewLine(selectedBytes)) {
            contentMatcher = createWordMatcher(selectionPart, byteToStringFunction.apply(selectedBytes));
        } else {
            final TemplateMatcher binaryMatcher = new Binary(selectedBytes);
            binaryMatcher.setPart(selectionPart);
            contentMatcher = binaryMatcher;
        }

        return contentMatcher;
    }

    public static TransformedRequest transformRequestWithPayloads(Requests.AttackType attackType, String request) {
        final Matcher matcher = INTRUDER_PAYLOAD_PATTERN.matcher(request);

        return attackType == Requests.AttackType.batteringram ? handleBatteringRam(attackType, request, matcher)
                                                              : handleMultiPayloadAttackTypes(attackType, request, matcher);
    }

    private static TransformedRequest handleMultiPayloadAttackTypes(Requests.AttackType attackType, String request, Matcher matcher) {
        final Map<String, List<String>> payloadParameters = new LinkedHashMap<>();

        final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
            final String indexedParameterName = BASE_PAYLOAD_PARAMETER_NAME + index;
            payloadParameters.put(indexedParameterName, new ArrayList<>(List.of(payloadParameter)));
            return indexedParameterName;
        };

        final String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
        return new TransformedRequest(attackType, transformedRequest, payloadParameters);
    }

    private static TransformedRequest handleBatteringRam(Requests.AttackType attackType, String request, Matcher matcher) {
        final List<String> payloadParameters = new ArrayList<>();
        final BiFunction<Integer, String, String> payloadFunction = (index, payloadParameter) -> {
            payloadParameters.add(payloadParameter);
            return BASE_PAYLOAD_PARAMETER_NAME;
        };

        final String transformedRequest = transformRawRequest(request, matcher, payloadFunction);
        return new TransformedRequest(attackType, transformedRequest, Map.of(BASE_PAYLOAD_PARAMETER_NAME, payloadParameters));
    }

    private static String transformRawRequest(String request, Matcher matcher, BiFunction<Integer, String, String> payloadFunction) {
        String transformedRequest = request;
        int index = 1;
        while (matcher.find()) {
            final String group = matcher.group();
            final String payloadParameter = group.substring(1, group.length() - 1);

            final String newParamName = payloadFunction.apply(index++, payloadParameter);

            transformedRequest = transformedRequest.replace(group, PAYLOAD_START_MARKER + newParamName + PAYLOAD_END_MARKER);
        }
        return transformedRequest;
    }

    private static TemplateMatcher createWordMatcher(TemplateMatcher.Part selectionPart, String selectedString) {
        final Word wordMatcher;
        if (selectionPart == TemplateMatcher.Part.header) {
            wordMatcher = new Word(selectedString.split(Utils.CRLF));
        } else {
            // TODO could make a config to enable the user to decide on the normalization
            final String selectedStringWithNormalizedNewLines = selectedString.replaceAll(Utils.CRLF, String.valueOf(Utils.LF)).replace(Utils.CR, Utils.LF);
            final String[] words = selectedStringWithNormalizedNewLines.split(String.valueOf(Utils.LF));
            wordMatcher = new Word(words);

            if (words.length > 1) {
                wordMatcher.setCondition(TemplateMatcher.Condition.or);
            }
        }
        wordMatcher.setPart(selectionPart);
        return wordMatcher;
    }

    private static String addNewLineBeforeProperty(String input, String propertyName) {
        return addNewLineBeforeProperty(input, propertyName, Collections.emptyList());
    }

    private static String addNewLineBeforeProperty(String input, String propertyName, List<String> values) {
        final String valuesRegexOrExpression = values.isEmpty() ? ""
                                                                : String.format(" (?:%s)", String.join("|", values));

        final Pattern pattern = Pattern.compile(String.format("(^\\s*%s:%s$)", propertyName, valuesRegexOrExpression), Pattern.MULTILINE);
        final Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            final String group = matcher.group(1);
            input = input.replace(group, "\n" + group);
        }

        return input;
    }
}
