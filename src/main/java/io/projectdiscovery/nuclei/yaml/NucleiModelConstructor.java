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

import io.projectdiscovery.nuclei.model.*;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.error.YAMLException;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;

import java.util.List;
import java.util.stream.Stream;

class NucleiModelConstructor extends Constructor {

    @Override
    protected Object newInstance(Node node) {
        if (node.getType() == TemplateMatcher.class) {
            try {
                final List<NodeTuple> templateMatcherNodeValues = ((MappingNode) node).getValue();

                for (NodeTuple templateMatcherNodeValue : templateMatcherNodeValues) {
                    final String attributeName = ((ScalarNode) templateMatcherNodeValue.getKeyNode()).getValue();
                    if (TemplateMatcher.TYPE_FIELD_NAME.equalsIgnoreCase(attributeName)) {
                        final ScalarNode templateMatcherScalarNodeValue = (ScalarNode) templateMatcherNodeValue.getValueNode();
                        final String attributeValue = templateMatcherScalarNodeValue.getValue();

                        // it would only worth generalizing this, if there would be multiple deserializable interface types
                        Stream.of(Word.class, Status.class, Binary.class)
                              .filter(templateMatcherClass -> templateMatcherClass.getSimpleName().equalsIgnoreCase(attributeValue))
                              .findFirst()
                              .map(templateMatcherClass -> {
                                  node.setType(templateMatcherClass);
                                  return templateMatcherClass;
                              })
                              .orElseThrow(() -> new YAMLException(String.format("Instantiation of the '%s' TemplateMatcher not yet implemented!", attributeValue)));
                        break; // the type has been found, we can break from the for
                    }
                }
            } catch (final ClassCastException e) {
                throw new YAMLException("Could not instantiate TemplateMatcher");
            }
        }

        return super.newInstance(node);
    }
}
