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

package io.projectdiscovery.utils.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.stream.IntStream;

public final class SwingUtils {

    private SwingUtils() {
    }

    public static void openWebPage(String url) throws IOException, URISyntaxException {
        openWebPage(new URL(url).toURI());
    }

    public static void openWebPage(URL url) throws IOException, URISyntaxException {
        openWebPage(url.toURI());
    }

    public static void openWebPage(URI uri) throws IOException {
        final Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            desktop.browse(uri);
        }
    }

    public static void setTabSupportKeyboardShortcuts(JTabbedPane tabbedPane, JComponent parentComponent) {
        SwingUtils.setKeyboardShortcut(parentComponent, KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK), () -> tabbedPane.remove(tabbedPane.getSelectedIndex()));

        IntStream.rangeClosed(1, 9).forEach(keyIndex -> {
            final char digit = Character.forDigit(keyIndex, 16);
            SwingUtils.setKeyboardShortcut(parentComponent, KeyStroke.getKeyStroke(digit, InputEvent.CTRL_DOWN_MASK), () -> {

                final int tabIndex = keyIndex - 1;
                if (tabbedPane.getTabCount() > tabIndex) {
                    tabbedPane.setSelectedIndex(tabIndex);
                }
            });
        });
    }

    public static void setKeyboardShortcut(JComponent rootPane, int keyCode, Runnable actionPerformed) {
        setKeyboardShortcut(rootPane, KeyStroke.getKeyStroke(keyCode, 0), actionPerformed);
    }

    public static void setKeyboardShortcut(JComponent rootPane, KeyStroke keyStroke, Runnable actionPerformed) {
        setKeyboardShortcut(rootPane, keyStroke, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                actionPerformed.run();
            }
        });
    }

    public static void setKeyboardShortcut(JComponent container, KeyStroke keyStroke, Action action) {
        final InputMap frameInputMap = container.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        final ActionMap frameActionMap = container.getActionMap();

        final String shortcutKey = keyStroke.toString();
        frameInputMap.put(keyStroke, shortcutKey);

        frameActionMap.put(shortcutKey, action);
    }
}
