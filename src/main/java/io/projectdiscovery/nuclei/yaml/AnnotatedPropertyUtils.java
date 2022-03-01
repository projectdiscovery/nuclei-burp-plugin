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

package io.projectdiscovery.nuclei.yaml;

import io.projectdiscovery.nuclei.model.util.YamlProperty;
import org.yaml.snakeyaml.error.YAMLException;
import org.yaml.snakeyaml.introspector.*;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;

class AnnotatedPropertyUtils extends PropertyUtils {

    @Override
    protected Map<String, Property> getPropertiesMap(Class<?> type, BeanAccess beanAccess) {
        final Map<String, Property> properties = new LinkedHashMap<>();

        if (beanAccess == BeanAccess.FIELD) {
            return super.getPropertiesMap(type, beanAccess);
        } else {
            for (Class<?> currentClass = type; currentClass != null; currentClass = currentClass.getSuperclass()) {
                for (Field field : currentClass.getDeclaredFields()) {
                    final int modifiers = field.getModifiers();
                    if (!Modifier.isStatic(modifiers) && !Modifier.isTransient(modifiers)) {
                        final YamlProperty yamlPropertyAnnotation = field.getAnnotation(YamlProperty.class);
                        if (yamlPropertyAnnotation != null) {
                            final String yamlPropertyName = yamlPropertyAnnotation.value();
                            if (yamlPropertyName.equals("")) {
                                final String transformedFieldName = AnnotatedPropertyUtils.toSnakeCase(field.getName());
                                properties.put(transformedFieldName, new CustomNameFieldProperty(transformedFieldName, field));
                            } else {
                                properties.put(yamlPropertyName, new CustomNameFieldProperty(yamlPropertyName, field));
                            }
                        }
                    }
                }
            }
        }

        if (properties.isEmpty()) {
            throw new YAMLException(String.format("No JavaBean properties found in '%s'.", type.getName()));
        }
        return properties;
    }

    private static String toSnakeCase(String input) {
        return input.replaceAll("([a-z]+)([A-Z]+)", "$1-$2").toLowerCase();
    }
}
