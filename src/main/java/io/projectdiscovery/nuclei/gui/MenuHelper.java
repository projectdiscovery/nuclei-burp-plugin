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
import javax.swing.event.HyperlinkEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Optional;
import java.util.function.Consumer;

public final class MenuHelper {

    private static final String TEMPLATE_DOCUMENTATION_URL = "https://nuclei.projectdiscovery.io/templating-guide/";
    private static final String ABOUT_MESSAGE = "<html>" +
                                                "<body%s>" +
                                                "Created by <a href=\"https://github.com/forgedhallpass\">@forgedhallpass</a>" +
                                                "<br>" +
                                                "Powered by <a href=\"https://projectdiscovery.io\">ProjectDiscovery.io</a>" +
                                                "</body>" +
                                                "</html>";

    private final Consumer<String> errorMessageConsumer;

    public MenuHelper(Consumer<String> errorMessageConsumer) {
        this.errorMessageConsumer = errorMessageConsumer;
    }

    public JMenuBar createMenuBar() {
        final JMenu menu = new JMenu("Help");
        menu.setMnemonic(KeyEvent.VK_H);

        menu.add(createAboutMenuItem());
        menu.add(createHelpMenuItem());
        menu.add(createShortcutsMenuItem());

        final JMenuBar menuBar = new JMenuBar();
        menuBar.add(menu);
        return menuBar;
    }

    public static void openDocumentationLink(Consumer<String> errorMessageConsumer) {
        try {
            SwingUtils.openWebPage(TEMPLATE_DOCUMENTATION_URL);
        } catch (IOException | URISyntaxException e) {
            errorMessageConsumer.accept("Launching the default browser is not allowed: " + e.getMessage());
        }
    }

    private JMenuItem createHelpMenuItem() {
        final JMenuItem documentationMenuItem = new JMenuItem("Documentation");
        documentationMenuItem.addActionListener(event -> openDocumentationLink(this.errorMessageConsumer));
        return documentationMenuItem;
    }

    private JMenuItem createAboutMenuItem() {
        final String aboutTitle = "About";
        final JMenuItem aboutMenuItem = new JMenuItem(aboutTitle);
        aboutMenuItem.addActionListener(e -> {
            final URL pdIconUrl = SettingsPanel.class.getResource("/ProjectDiscovery-Icon.png");
            final String bodyStyle = getHtmlBodyStyle();

            if (pdIconUrl != null) {
                JOptionPane.showMessageDialog(null, new HyperlinkPane(String.format(ABOUT_MESSAGE, bodyStyle)), aboutTitle, JOptionPane.PLAIN_MESSAGE, new ImageIcon(pdIconUrl));
            } else {
                JOptionPane.showMessageDialog(null, new HyperlinkPane(String.format(ABOUT_MESSAGE, bodyStyle)), aboutTitle, JOptionPane.INFORMATION_MESSAGE);
            }
        });
        return aboutMenuItem;
    }

    private String getHtmlBodyStyle() {
        return Optional.ofNullable(UIManager.getColor("Panel.background"))
                       .map(color -> String.format(" style=\"background-color:rgb(%d, %d, %d);\"",
                                                   color.getRed(),
                                                   color.getGreen(),
                                                   color.getBlue()))
                       .orElse("");
    }

    private JMenuItem createShortcutsMenuItem() {
        final String menuName = "Productivity";
        final JMenuItem documentationMenuItem = new JMenuItem(menuName);
        documentationMenuItem.addActionListener(event -> {
            final String[] messages = {
                    "F1: Open nuclei template documentation",
                    "",
                    "Ctrl + Enter: Execute",
                    "Ctrl + Shift + E: Jump to template editor",
                    "Ctrl + L: Jump to CLI input field",
                    "Ctrl + R: Show CLI argument helper",
                    "Ctrl + S: Save the current template",
                    "Ctrl + Plus/Minus: Increase/decrease font size",
                    "Ctrl + Q: Quit",
                    "",
                    "Tab Support:",
                    "Ctrl + Tab or Ctrl + PageDown: Open next tab",
                    "Ctrl + Shift + Tab or Ctrl + PageUp: Open previous tab",
                    "Ctrl + [1-9]: Jump to n-th tab",
                    "Mouse Scroll Up/Down over the tabs: Navigate to next or previous tab",
                    "Ctrl + W or Middle Mouse Button Click: Close current tab"
            };
            JOptionPane.showMessageDialog(null, String.join("\n", messages), menuName, JOptionPane.INFORMATION_MESSAGE);
        });
        return documentationMenuItem;
    }

    private class HyperlinkPane extends JEditorPane {
        public HyperlinkPane(String content) {
            super("text/html", content);

            setEditable(false);
            setBorder(null);

            addHyperlinkListener(e -> {
                if (e.getEventType().equals(HyperlinkEvent.EventType.ACTIVATED)) {
                    try {
                        SwingUtils.openWebPage(e.getURL());
                    } catch (IOException | URISyntaxException ex) {
                        MenuHelper.this.errorMessageConsumer.accept("Launching the default browser is not allowed: " + ex.getMessage());
                    }
                }
            });
        }
    }
}
