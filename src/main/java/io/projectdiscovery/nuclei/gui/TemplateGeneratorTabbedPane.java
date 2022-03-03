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

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.util.List;
import java.util.concurrent.Executors;

class TemplateGeneratorTabbedPane extends JTabbedPane {
    private final List<TemplateGeneratorTab> templateGeneratorTabs;

    public TemplateGeneratorTabbedPane(List<TemplateGeneratorTab> templateGeneratorTabs) {
        super(TOP, SCROLL_TAB_LAYOUT);
        this.templateGeneratorTabs = templateGeneratorTabs;

        this.addMouseWheelListener(this::navigateTabsWithMouseScroll);
        this.addMouseListener(closeTabWithMiddleMouseButtonAdapter());

        this.setVisible(true);
    }

    @Override
    public void remove(int index) {
        if (index >= 0) {
            Executors.newSingleThreadExecutor().submit(() -> this.templateGeneratorTabs.get(index).cleanup());
            this.templateGeneratorTabs.remove(index);
            super.remove(index);
        }
    }

    private void navigateTabsWithMouseScroll(MouseWheelEvent e) {
        final int selectedIndex = this.getSelectedIndex();

        int newIndex = e.getWheelRotation() < 0 ? selectedIndex - 1
                                                : selectedIndex + 1;

        final int tabCount = this.getTabCount();
        if (newIndex >= tabCount) {
            newIndex = 0;
        } else if (newIndex < 0) {
            newIndex = tabCount - 1;
        }

        this.setSelectedIndex(newIndex);
    }

    private MouseAdapter closeTabWithMiddleMouseButtonAdapter() {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON2) {
                    removeTab();
                } else {
                    super.mouseClicked(e);
                }
            }
        };
    }

    public void removeTab() {
        this.remove(this.getSelectedIndex());
    }
}
