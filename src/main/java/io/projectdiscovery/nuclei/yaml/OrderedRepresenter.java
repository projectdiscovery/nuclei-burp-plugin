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

import io.projectdiscovery.nuclei.model.util.YamlPropertyOrder;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.util.*;
import java.util.stream.Collectors;

class OrderedRepresenter extends Representer {

    private final PropertyUtils propertyUtils;

    OrderedRepresenter(PropertyUtils propertyUtils) {
        this.propertyUtils = propertyUtils;
    }

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
            addClassTag(javaBean.getClass(), Tag.MAP); // remove class tags (e.g. !!packageName.ClassName)
        }

        return super.representJavaBean(properties, javaBean);
    }

    @Override
    protected Set<Property> getProperties(Class<?> type) {
        Set<Property> propertySet = this.typeDefinitions.containsKey(type) ? this.typeDefinitions.get(type).getProperties()
                                                                           : this.propertyUtils.getProperties(type);

        final YamlPropertyOrder annotation = type.getAnnotation(YamlPropertyOrder.class);
        if (annotation != null) {
            final List<String> order = Arrays.asList(annotation.value());
            propertySet = propertySet.stream()
                                     .sorted(Comparator.comparingInt(o -> order.indexOf(o.getName())))
                                     .collect(Collectors.toCollection(LinkedHashSet::new));
        }

        return propertySet;
    }
}
