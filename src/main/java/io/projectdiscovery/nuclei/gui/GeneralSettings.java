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

import io.projectdiscovery.nuclei.gui.settings.SettingsPanel;
import io.projectdiscovery.utils.Utils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

public class GeneralSettings {

    private final Consumer<String> outputConsumer;
    private final Consumer<String> errorConsumer;
    private final BiConsumer<String, String> extensionSettingSaver;
    private final Function<String, String> extensionSettingLoader;

    GeneralSettings(GeneralSettings generalSettings) {
        this.outputConsumer = generalSettings.outputConsumer;
        this.errorConsumer = generalSettings.errorConsumer;
        this.extensionSettingSaver = generalSettings.extensionSettingSaver;
        this.extensionSettingLoader = generalSettings.extensionSettingLoader;
    }

    GeneralSettings(Builder builder) {
        this.outputConsumer = builder.outputConsumer;
        this.errorConsumer = builder.errorConsumer;
        this.extensionSettingSaver = builder.extensionSettingSaver;
        this.extensionSettingLoader = builder.extensionSettingLoader;
    }

    public String getAuthor() {
        return loadExtensionSetting(SettingsPanel.AUTHOR_SETTING_NAME);
    }

    Optional<Path> getNucleiPathSetting() {
        return Optional.ofNullable(loadExtensionSetting(SettingsPanel.NUCLEI_PATH_SETTING_NAME)).map(Paths::get);
    }

    public Path getTemplatePath() {
        return Optional.ofNullable(loadExtensionSetting(SettingsPanel.TEMPLATE_PATH_SETTING_NAME))
                       .map(Paths::get)
                       .orElseGet(Utils::getTempPath);
    }

    public boolean isDetachedGeneratorWindow() {
        return Boolean.parseBoolean(loadExtensionSetting(SettingsPanel.DETACHED_TABS_SETTING_NAME));
    }

    public Integer getFontSize() {
        return Optional.ofNullable(loadExtensionSetting(SettingsPanel.FONT_SIZE_SETTING_NAME))
                       .map(Integer::parseInt)
                       .orElse(SettingsPanel.DEFAULT_FONT_SIZE);
    }

    public void saveFontSize(int fontSize) {
        saveExtensionSetting(SettingsPanel.FONT_SIZE_SETTING_NAME, String.valueOf(fontSize));
    }

    public String loadExtensionSetting(String key) {
        return this.extensionSettingLoader.apply(key);
    }

    public void saveExtensionSetting(String key, String value) {
        this.extensionSettingSaver.accept(key, value);
    }

    public void logError(String content) {
        this.errorConsumer.accept(content);
    }

    public void log(String content) {
        this.outputConsumer.accept(content);
    }

    public static final class Builder {
        private Consumer<String> errorConsumer;
        private Consumer<String> outputConsumer;
        private BiConsumer<String, String> extensionSettingSaver;
        private Function<String, String> extensionSettingLoader;

        public Builder() {
        }

        public Builder withErrorConsumer(Consumer<String> errorConsumer) {
            this.errorConsumer = errorConsumer;
            return this;
        }

        public Builder withOutputConsumer(Consumer<String> outputConsumer) {
            this.outputConsumer = outputConsumer;
            return this;
        }

        public Builder withExtensionSettingSaver(BiConsumer<String, String> extensionSettingSaver) {
            this.extensionSettingSaver = extensionSettingSaver;
            return this;
        }

        public Builder withExtensionSettingLoader(Function<String, String> extensionSettingLoader) {
            this.extensionSettingLoader = extensionSettingLoader;
            return this;
        }

        public GeneralSettings build() {
            if (this.errorConsumer == null) {
                this.errorConsumer = System.err::println;
            }

            if (this.outputConsumer == null) {
                this.outputConsumer = System.out::println;
            }

            if (this.extensionSettingLoader == null) {
                this.extensionSettingLoader = v -> null;
            }

            if (this.extensionSettingSaver == null) {
                this.extensionSettingSaver = (k, v) -> this.errorConsumer.accept("Extension setting persistence was not configured");
            }

            return new GeneralSettings(this);
        }
    }
}
