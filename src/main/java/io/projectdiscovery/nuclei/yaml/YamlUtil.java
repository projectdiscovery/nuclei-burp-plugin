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

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.BaseConstructor;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.representer.Representer;

public final class YamlUtil {

    private static final Yaml YAML_INSTANCE = createYamlInstance();

    private YamlUtil() {
    }

    public static String dump(Object data) {
        return YAML_INSTANCE.dumpAsMap(data);
    }

    public static <T> T load(String data, Class<T> modelClass) {
        return YAML_INSTANCE.loadAs(data, modelClass);
    }

    private static Yaml createYamlInstance() {
        final PropertyUtils propertyUtils = new AnnotatedPropertyUtils();

        final BaseConstructor baseConstructor = new NucleiModelConstructor();
        baseConstructor.setPropertyUtils(propertyUtils);

        final Representer representer = new OrderedRepresenter(propertyUtils);
        final DumperOptions options = createDumperOptions();
        final LoaderOptions loaderOptions = new LoaderOptions();

        return new Yaml(baseConstructor, representer, options, loaderOptions);
    }

    private static DumperOptions createDumperOptions() {
        final DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setIndicatorIndent(2);
        options.setIndentWithIndicator(true);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        return options;
    }
}
