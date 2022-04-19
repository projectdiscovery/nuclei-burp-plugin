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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;
import java.util.function.Consumer;

public class FilterableListWindow extends JFrame {

    private final Map<String, String> listModelMap;
    private final JList<String> jList;
    private final JTextField textField;

    public FilterableListWindow(Map<String, String> listModelMap, Consumer<String> selectedValueConsumerOnAction) {
        this.listModelMap = listModelMap;

        this.jList = createJList();
        this.jList.addKeyListener(createOnEnterPressedAdapter(selectedValueConsumerOnAction));
        this.jList.addMouseListener(createDoubleClickAdapter(selectedValueConsumerOnAction));

        this.textField = createTextField();
        this.textField.addActionListener(e -> onActionPerformed(this.jList.getModel().getElementAt(0), selectedValueConsumerOnAction));

        this.setLayout(new BorderLayout());
        this.add(new JScrollPane(this.jList), BorderLayout.PAGE_START);
        this.add(this.textField, BorderLayout.PAGE_END);

        SwingUtils.setKeyboardShortcut(this.getRootPane(), KeyEvent.VK_ESCAPE, this::dispose);
        this.addWindowListener(createDisposeOnFocusLostWindowAdapter());
        this.setUndecorated(true);
        this.pack();
        this.setVisible(true);
        this.setLocationRelativeTo(null);
    }

    private WindowAdapter createDisposeOnFocusLostWindowAdapter() {
        return new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                super.windowOpened(e);
                FilterableListWindow.this.textField.requestFocus();
            }

            @Override
            public void windowDeactivated(WindowEvent e) {
                super.windowDeactivated(e);
                FilterableListWindow.this.dispose();
            }

            @Override
            public void windowLostFocus(WindowEvent e) {
                super.windowLostFocus(e);
                FilterableListWindow.this.dispose();
            }
        };
    }

    private MouseAdapter createDoubleClickAdapter(Consumer<String> selectedValueConsumerOnAction) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2) {
                    final int selectionIndex = FilterableListWindow.this.jList.locationToIndex(event.getPoint());
                    final String selectedElement = FilterableListWindow.this.jList.getModel().getElementAt(selectionIndex);
                    onActionPerformed(selectedElement, selectedValueConsumerOnAction);
                } else {
                    super.mouseClicked(event);
                }
            }
        };
    }

    private KeyAdapter createOnEnterPressedAdapter(Consumer<String> selectedValueConsumerOnAction) {
        return new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    final String selectedValue = FilterableListWindow.this.jList.getSelectedValue();
                    onActionPerformed(selectedValue, selectedValueConsumerOnAction);
                } else {
                    super.keyPressed(e);
                }
            }
        };
    }

    private void onActionPerformed(String selectedElement, Consumer<String> onActionPerformed) {
        final String selectedShortFlag = FilterableListWindow.this.listModelMap.get(selectedElement);
        onActionPerformed.accept(selectedShortFlag);
        FilterableListWindow.this.dispose();
    }

    private JTextField createTextField() {
        final JTextField textField = new JTextField(15);
        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }

            private void filter() {
                final String filter = textField.getText();
                filterModel((DefaultListModel<String>) FilterableListWindow.this.jList.getModel(), filter);
            }
        });
        return textField;
    }

    private JList<String> createJList() {
        final JList<String> list = new JList<>(createDefaultListModel());
        list.setVisibleRowCount(6);
        return list;
    }

    private ListModel<String> createDefaultListModel() {
        final DefaultListModel<String> model = new DefaultListModel<>();
        model.addAll(this.listModelMap.keySet());
        return model;
    }

    public void filterModel(DefaultListModel<String> model, String filter) {
        for (String value : this.listModelMap.keySet()) {
            if (value.contains(filter)) {
                if (!model.contains(value)) {
                    model.addElement(value);
                }
            } else {
                if (model.contains(value)) {
                    model.removeElement(value);
                }
            }
        }
    }

    public JList<String> getList() {
        return this.jList;
    }
}
