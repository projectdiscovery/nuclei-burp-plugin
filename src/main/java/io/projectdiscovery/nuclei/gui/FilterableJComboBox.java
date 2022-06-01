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

import io.projectdiscovery.utils.Utils;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

public final class FilterableJComboBox extends JComboBox<String> {

    private static final Integer[] KEYS_TO_IGNORE = {KeyEvent.VK_ENTER, KeyEvent.VK_BACK_SPACE, KeyEvent.VK_ESCAPE};
    private final Deque<String> commandHistory;

    public FilterableJComboBox(String item) {
        this(new String[]{item});
    }

    public FilterableJComboBox(String[] items) {
        super(items);

        this.commandHistory = new ArrayDeque<>(Arrays.asList(items));

        this.setEditable(true);

        final JTextField textField = getTextField();

        textField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent keyEvent) {
                final String text = textField.getText();
                if (keyEvent.getModifiersEx() == 0 && !keyEvent.isActionKey() && Arrays.stream(KEYS_TO_IGNORE).noneMatch(k -> k == keyEvent.getKeyCode())) {
                    filterComboModel(text);
                } else {
                    if (Utils.isBlank(text)) {
                        if (FilterableJComboBox.this.getModel().getSize() < FilterableJComboBox.this.commandHistory.size()) {
                            FilterableJComboBox.this.setModel(new DefaultComboBoxModel<>(FilterableJComboBox.this.commandHistory.toArray(String[]::new)));
                            textField.setText("");
                        }
                    }
                    super.keyPressed(keyEvent);
                }
            }
        });

        textField.addActionListener(e -> updateComboModel(textField));
    }

    JTextField getTextField() {
        final ComboBoxEditor comboBoxEditor = this.getEditor();
        return (JTextField) comboBoxEditor.getEditorComponent();
    }

    /**
     * If a new command is entered, save it and add to the model.
     * Both new and re-executed commands are added/moved to the top of the history.
     */
    private void updateComboModel(JTextField textfield) {
        final String command = textfield.getText();
        if (this.commandHistory.stream().noneMatch(v -> v.equals(command))) {
            this.commandHistory.addFirst(command);
            this.setModel(new DefaultComboBoxModel<>(this.commandHistory.toArray(String[]::new)));
        } else {
            this.commandHistory.remove(command);
            this.commandHistory.addFirst(command);
        }
    }

    private void filterComboModel(String enteredText) {
        if (Utils.isBlank(enteredText)) {
            this.hidePopup();
        } else {
            final String[] matchedCommands = this.commandHistory.stream().filter(v -> v.contains(enteredText)).toArray(String[]::new);
            if (matchedCommands.length > 0) {
                this.setModel(new DefaultComboBoxModel<>(matchedCommands));
                this.setSelectedItem(enteredText);
                this.showPopup();
            } else {
                this.hidePopup();
            }
        }
    }
}
