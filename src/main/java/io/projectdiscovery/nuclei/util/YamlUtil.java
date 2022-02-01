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

import io.projectdiscovery.nuclei.model.util.YamlProperty;
import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;
import org.yaml.snakeyaml.introspector.*;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Collectors;

public final class YamlUtil {

    private YamlUtil() {
    }

    public static String dump(Object data) {

        final PropertyUtils propertyUtils = new PropertyUtils() {
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
                                        final String transformedFieldName = toSnakeCase(field.getName());
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
                    throw new YAMLException("No JavaBean properties found in " + type.getName());
                }
                return properties;
            }

            class CustomNameFieldProperty extends GenericProperty {

                private final FieldProperty fieldProperty;

                public CustomNameFieldProperty(String name, Field field) {
                    super(name, field.getType(), field.getGenericType());
                    this.fieldProperty = new FieldProperty(field);
                }

                @Override
                public void set(Object object, Object value) throws Exception {
                    this.fieldProperty.set(object, value);
                }

                @Override
                public Object get(Object object) {
                    return this.fieldProperty.get(object);
                }

                @Override
                public List<Annotation> getAnnotations() {
                    return this.fieldProperty.getAnnotations();
                }

                @Override
                public <A extends Annotation> A getAnnotation(Class<A> annotationType) {
                    return this.fieldProperty.getAnnotation(annotationType);
                }
            }

            @Override
            public Property getProperty(Class<?> type, String name) {
                // TODO snake case to camel case, for deserialization
                return super.getProperty(type, name);
            }
        };

        final Representer representer = new Representer() {
            @Override
            protected NodeTuple representJavaBeanProperty(Object javaBean, Property property, Object propertyValue, Tag customTag) {
                if (Objects.isNull(propertyValue)) {
                    return null; // skip fields with null value
                }
                return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
            }

            @Override
            protected MappingNode representJavaBean(Set<Property> properties, Object javaBean) {
                if (!this.classTags.containsKey(javaBean.getClass())) {
                    addClassTag(javaBean.getClass(), Tag.MAP);
                }

                return super.representJavaBean(properties, javaBean);
            }

            @Override
            protected Set<Property> getProperties(Class<?> type) {
                Set<Property> propertySet = this.typeDefinitions.containsKey(type) ? this.typeDefinitions.get(type).getProperties()
                                                                                   : propertyUtils.getProperties(type);

                final YamlPropertyOrder annotation = type.getAnnotation(YamlPropertyOrder.class);
                if (annotation != null) {
                    final List<String> order = Arrays.asList(annotation.value());
                    propertySet = propertySet.stream()
                                             .sorted(Comparator.comparingInt(o -> order.indexOf(o.getName())))
                                             .collect(Collectors.toCollection(LinkedHashSet::new));
                }

                return propertySet;
            }
        };

        representer.setPropertyUtils(propertyUtils);

        final DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        final Yaml yaml = new Yaml(representer, options);
        return yaml.dumpAsMap(data);
    }

    private static String toSnakeCase(String input) {
        return input.replaceAll("([a-z]+)([A-Z]+)", "$1-$2").toLowerCase();
    }
}
