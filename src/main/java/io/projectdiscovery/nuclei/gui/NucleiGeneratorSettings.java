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

package io.projectdiscovery.nuclei.gui;

import io.projectdiscovery.nuclei.util.NucleiUtils;

import java.net.URL;
import java.nio.file.Path;
import java.util.Map;

public final class NucleiGeneratorSettings extends GeneralSettings {

    private final URL targetUrl;
    private final String templateYaml;
    private final Map<String, String> yamlFieldDescriptionMap;

    private NucleiGeneratorSettings(GeneralSettings generalSettings, Builder builder) {
        super(generalSettings);
        this.targetUrl = builder.targetUrl;
        this.templateYaml = builder.templateYaml;
        this.yamlFieldDescriptionMap = builder.yamlFieldDescriptionMap;
    }

    public Path getNucleiPath() {
        return NucleiUtils.getConfiguredNucleiPath(getNucleiPathSetting(), NucleiUtils.getNucleiBinaryName());
    }

    public URL getTargetUrl() {
        return this.targetUrl;
    }

    public String getTemplateYaml() {
        return this.templateYaml;
    }

    public Map<String, String> getYamlFieldDescriptionMap() {
        return this.yamlFieldDescriptionMap;
    }

    public static final class Builder {
        private final GeneralSettings generalSettings;
        private final URL targetUrl;
        private final String templateYaml;
        private Map<String, String> yamlFieldDescriptionMap;

        public Builder(GeneralSettings generalSettings, URL targetUrl, String templateYaml) {
            this.generalSettings = generalSettings;
            this.targetUrl = targetUrl;
            this.templateYaml = templateYaml;
        }

        public Builder withYamlFieldDescriptionMap(Map<String, String> yamlFieldDescriptionMap) {
            this.yamlFieldDescriptionMap = yamlFieldDescriptionMap;
            return this;
        }

        public NucleiGeneratorSettings build() {
            return new NucleiGeneratorSettings(this.generalSettings, this);
        }
    }
}
