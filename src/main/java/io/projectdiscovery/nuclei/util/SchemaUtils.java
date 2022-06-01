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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class SchemaUtils {

    private SchemaUtils() {
    }

    private static final String NUCLEI_JSON_SCHEMA_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei/master/nuclei-jsonschema.json";

    public static Map<String, String> retrieveYamlFieldWithDescriptions() throws IOException {
        final URL jsonSchemaUrl = new URL(NUCLEI_JSON_SCHEMA_URL);
        try (final InputStreamReader inputStreamReader = new InputStreamReader(jsonSchemaUrl.openStream(), StandardCharsets.UTF_8)) {
            return retrieveYamlFieldWithDescriptions(inputStreamReader);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    // TODO find a more elegant way
    private static Map<String, String> retrieveYamlFieldWithDescriptions(InputStreamReader inputStreamReader) {
        final Map<String, String> result = new TreeMap<>();
        final Gson gson = new Gson();

        final Type type = new TypeToken<Map<String, Object>>() {
        }.getType();

        final Map<String, Object> parsedJsonSchema = gson.fromJson(inputStreamReader, type);

        final Map<String, Object> definitions = (Map<String, Object>) parsedJsonSchema.get("definitions");
        for (Map.Entry<String, Object> definitionEntry : definitions.entrySet()) {
            final Map<String, Map> properties = ((Map<String, Map>) definitionEntry.getValue()).get("properties");

            if (properties != null) {
                for (Map.Entry<String, Map> field : properties.entrySet()) {
                    result.put(field.getKey(), (String) field.getValue().get("description"));
                }
            } else {
                final Map<String, Object> enumFieldMap = ((Map<String, Object>) definitionEntry.getValue());
                final Collection<String> enums = (Collection<String>) enumFieldMap.get("enum");

                if (enums != null) {
                    for (String enumValue : enums) {
                        result.put(enumValue, (String) enumFieldMap.get("description"));
                    }
                } else {
                    System.err.println(enumFieldMap);
                }
            }
        }
        return result;
    }
}
