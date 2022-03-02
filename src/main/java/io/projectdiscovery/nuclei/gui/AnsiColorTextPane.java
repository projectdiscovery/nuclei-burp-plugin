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
import javax.swing.text.*;
import java.awt.*;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AnsiColorTextPane extends JTextPane {

    private static final Pattern ANSI_COLOR_PATTERN = Pattern.compile("((\u001B\\[(?:\\d+;)*\\d{1,3}m)(.*?)\u001B\\[0m)");

    private final Consumer<String> errorLogger;

    public AnsiColorTextPane(int fontSize, Consumer<String> errorLogger) {
        super();
        super.putClientProperty(RenderingHints.KEY_ANTIALIASING, Boolean.TRUE);
        super.setFont(new Font(Font.MONOSPACED, Font.PLAIN, fontSize));
        this.errorLogger = errorLogger;
    }

    public AnsiColorTextPane() {
        this(SettingsPanel.DEFAULT_FONT_SIZE, System.err::println);
    }

    public void appendText(String content, boolean noColor) {
        if (noColor) {
            appendText(content);
        } else {
            final Matcher matcher = ANSI_COLOR_PATTERN.matcher(content);
            appendText(matcher, content, 0);
        }
    }

    public void appendText(String content) {
        appendRichText(content, null);
    }

    private void appendText(Matcher matcher, String textContent, int start) {
        if (matcher.find()) {
            appendText(textContent.substring(start, matcher.start()));
            appendRichText(matcher.group(3), createAnsiAttributes(matcher.group(2)));

            appendText(matcher, textContent, matcher.end());
        } else {
            appendText(textContent.substring(start));
        }
    }

    private void appendRichText(String content, AttributeSet attributeSet) {
        final Document document = this.getDocument();

        try {
            document.insertString(document.getLength(), content, attributeSet);
        } catch (BadLocationException e) {
            this.errorLogger.accept(e.getMessage());
        }
    }

    private AttributeSet createAnsiAttributes(String content) {
        final SimpleAttributeSet simpleAttributeSet = new SimpleAttributeSet();

        if (content.equals("\u001B[1m")) {
            StyleConstants.setBold(simpleAttributeSet, true);
        } else if (content.equals("\u001B[4m")) {
            StyleConstants.setUnderline(simpleAttributeSet, true);
        } else {
            Optional.ofNullable(toColor(content)).ifPresent(color -> StyleConstants.setForeground(simpleAttributeSet, color));
            Optional.ofNullable(toBackgroundColor(content)).ifPresent(color -> StyleConstants.setBackground(simpleAttributeSet, color));
        }

        if (simpleAttributeSet.isEmpty()) {
            this.errorLogger.accept(String.format("ANSI escape '%s' not recognized!", content.replace('\u001B', Character.MIN_VALUE)));
        }

        return simpleAttributeSet;
    }

    private Color toBackgroundColor(String ansiColor) {
        switch (ansiColor) {
            case "\u001b[40m":
                return Color.BLACK.darker();
            case "\u001b[41m":
                return Color.RED.darker();
            case "\u001b[42m":
                return Color.GREEN.darker();
            case "\u001b[43m":
                return Color.YELLOW.darker();
            case "\u001b[44m":
                return Color.BLUE.darker();
            case "\u001b[45m":
                return Color.MAGENTA.darker();
            case "\u001b[46m":
                return Color.CYAN.darker();
            case "\u001b[47m":
                return Color.WHITE.darker();
            case "\u001b[40;1m":
                return Color.BLACK;
            case "\u001b[41;1m":
                return Color.RED;
            case "\u001b[42;1m":
                return Color.GREEN;
            case "\u001b[43;1m":
                return Color.YELLOW;
            case "\u001b[44;1m":
                return Color.BLUE;
            case "\u001b[45;1m":
                return Color.MAGENTA;
            case "\u001b[46;1m":
                return Color.CYAN;
            case "\u001b[47;1m":
                return Color.WHITE;
            case "\u001B[1;104m":
                return Color.BLUE.brighter();
            default:
                return null;
        }
    }

    private Color toColor(String ansiColor) {
        switch (ansiColor) {
            case "\u001B[30m":
            case "\u001B[0;30m":
                return Color.BLACK.darker();
            case "\u001B[31m":
            case "\u001B[0;31m":
                return Color.RED.darker();
            case "\u001B[32m":
            case "\u001B[0;32m":
                return Color.GREEN.darker();
            case "\u001B[33m":
            case "\u001B[0;33m":
                return Color.YELLOW.darker();
            case "\u001B[34m":
            case "\u001B[0;34m":
                return Color.BLUE.darker();
            case "\u001B[35m":
            case "\u001B[0;35m":
                return Color.MAGENTA.darker();
            case "\u001B[36m":
            case "\u001B[0;36m":
                return Color.CYAN.darker();
            case "\u001B[37m":
            case "\u001B[0;37m":
                return Color.WHITE.darker();
            case "\u001B[1;30m":
                return Color.BLACK;
            case "\u001B[1;31m":
                return Color.RED;
            case "\u001B[1;32m":
                return Color.GREEN;
            case "\u001B[1;33m":
            case "\u001B[92m":
                return Color.YELLOW;
            case "\u001B[1;34m":
                return Color.BLUE;
            case "\u001B[1;35m":
                return Color.MAGENTA;
            case "\u001B[93m":
                return Color.YELLOW.brighter();
            case "\u001B[38;5;208m":
                return Color.ORANGE;
            case "\u001B[1;36m":
            case "\u001B[94m":
                return Color.CYAN;
            default:
                return null;
        }
    }
}
