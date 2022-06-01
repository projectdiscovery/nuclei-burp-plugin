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

import io.projectdiscovery.utils.gui.SwingUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Optional;

public final class TemplateGeneratorEmbeddedContainer extends JPanel implements TemplateGeneratorTabContainer {

    private static volatile TemplateGeneratorEmbeddedContainer instance;

    private final TemplateGeneratorTabbedPane tabbedPane;

    private TemplateGeneratorEmbeddedContainer(GeneralSettings generalSettings) {
        super(new GridBagLayout());

        final GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.fill = GridBagConstraints.BOTH;

        this.tabbedPane = new TemplateGeneratorTabbedPane(generalSettings);
        this.add(this.tabbedPane, gridBagConstraints);

        SwingUtils.setTabSupportKeyboardShortcuts(this, this.tabbedPane);
        SwingUtils.setKeyboardShortcut(this, KeyEvent.VK_F1, () -> MenuHelper.openDocumentationLink(generalSettings::logError));
    }

    public static TemplateGeneratorEmbeddedContainer getInstance(GeneralSettings generalSettings) {
        if (instance == null) {
            synchronized (TemplateGeneratorEmbeddedContainer.class) {
                if (instance == null) {
                    instance = new TemplateGeneratorEmbeddedContainer(generalSettings);
                }
            }
        }

        return instance;
    }

    @Override
    public void addTab(TemplateGeneratorTab templateGeneratorTab) {
        this.tabbedPane.addTab(templateGeneratorTab);
    }

    @Override
    public JComponent getComponent() {
        return this;
    }

    @Override
    public TemplateGeneratorTabbedPane getTabbedPane() {
        return this.tabbedPane;
    }

    @Override
    public List<TemplateGeneratorTab> getTabs() {
        return this.tabbedPane.getTabs();
    }

    @Override
    public Optional<TemplateGeneratorTab> getTab(String tabName) {
        return this.tabbedPane.getTab(tabName);
    }
}

