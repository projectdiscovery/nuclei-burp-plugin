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

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.Map;

public class SettingsPanel extends JPanel {

    public static final String NUCLEI_PATH_VARIABLE = "nucleiPath";
    public static final String TEMPLATE_PATH_VARIABLE = "templatePath";
    public static final String AUTHOR_VARIABLE = "author";

    private final IBurpExtenderCallbacks callbacks;
    private JButton cancelButton;
    private JButton saveButton;
    private Map<String, JTextField> valueTextFieldMap;

    public SettingsPanel() {
        this(null);
    }

    public SettingsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.setLayout(new GridBagLayout());

        final JPanel formPanel = createFormPanel();
        final GridBagConstraints formPanelConstraints = new GridBagConstraints();
        formPanelConstraints.gridx = 0;
        formPanelConstraints.gridy = 0;
        formPanelConstraints.weightx = 0.4;
        formPanelConstraints.weighty = 0.95;
        formPanelConstraints.fill = GridBagConstraints.BOTH;

        this.add(formPanel, formPanelConstraints);

        final JPanel rightPanel = new JPanel();

        final GridBagConstraints rightPanelConstraints = new GridBagConstraints();
        rightPanelConstraints.gridx = 1;
        rightPanelConstraints.gridy = 0;
        rightPanelConstraints.weightx = 0.6;
        rightPanelConstraints.weighty = 0.95;
        rightPanelConstraints.fill = GridBagConstraints.BOTH;

        this.add(rightPanel, rightPanelConstraints);

        final JPanel buttonPanel = createButtonPanel();
        final GridBagConstraints buttonPanelConstraints = new GridBagConstraints();
        buttonPanelConstraints.gridx = 0;
        buttonPanelConstraints.gridy = 1;
        buttonPanelConstraints.gridwidth = 2;
        buttonPanelConstraints.weighty = 0.05;
        buttonPanelConstraints.fill = GridBagConstraints.BOTH;

        this.add(buttonPanel, buttonPanelConstraints);

        loadSavedFieldValues();
    }

    private JPanel createButtonPanel() {
        final JPanel buttonPanel = new JPanel(new GridBagLayout());

        saveButton = new JButton("Save");
        saveButton.setMnemonic(KeyEvent.VK_S);
        saveButton.setVisible(false);
        final GridBagConstraints saveConstraints = createButtonConstraints(1);
        saveButton.addActionListener(e -> {
            if (callbacks != null) {
                valueTextFieldMap.forEach((k, v) -> callbacks.saveExtensionSetting(k, v.getText()));
                setButtonsVisible(false);
            }
        });
        buttonPanel.add(saveButton, saveConstraints);

        cancelButton = new JButton("Cancel");
        cancelButton.setMnemonic(KeyEvent.VK_C);
        cancelButton.setVisible(false);
        cancelButton.addActionListener(e -> {
            if (callbacks != null) {
                loadSavedFieldValues();
                setButtonsVisible(false);
            }
        });
        final GridBagConstraints cancelConstraints = createButtonConstraints(2);
        buttonPanel.add(cancelButton, cancelConstraints);

        return buttonPanel;
    }

    private GridBagConstraints createButtonConstraints(int gridx) {
        final GridBagConstraints cancelConstraints = new GridBagConstraints();
        cancelConstraints.gridx = gridx;
        cancelConstraints.gridy = 2;
        cancelConstraints.fill = GridBagConstraints.CENTER;
        return cancelConstraints;
    }

    private JPanel createFormPanel() {
        final JPanel formPanel = new JPanel(new GridBagLayout());

        final JPanel topPanel = createFormTopPanel();
        final GridBagConstraints topPanelConstraints = new GridBagConstraints();
        topPanelConstraints.weightx = 1;
        topPanelConstraints.weighty = 0.05;
        topPanelConstraints.gridx = 0;
        topPanelConstraints.gridy = 0;
        topPanelConstraints.fill = GridBagConstraints.BOTH;

        formPanel.add(topPanel, topPanelConstraints);

        final JPanel bottomPanel = new JPanel(new GridBagLayout());
        final GridBagConstraints bottomConstraints = new GridBagConstraints();
        bottomConstraints.weightx = 1;
        bottomConstraints.weighty = 0.95;
        bottomConstraints.gridx = 0;
        bottomConstraints.gridy = 1;
        bottomConstraints.fill = GridBagConstraints.BOTH;

        formPanel.add(bottomPanel, bottomConstraints);

        return formPanel;
    }

    private JPanel createFormTopPanel() {
        final JPanel topPanel = new JPanel(new GridBagLayout());

        final JLabel heading = new JLabel("Template generator constants");
        heading.setFont(heading.getFont().deriveFont(Font.PLAIN, 18));
        final GridBagConstraints headerConstraints = new GridBagConstraints();
        headerConstraints.gridx = 0;
        headerConstraints.gridy = 0;
        headerConstraints.anchor = GridBagConstraints.LINE_START;
        headerConstraints.insets = new Insets(10, 10, 30, 10);
        topPanel.add(heading, headerConstraints);

        final String[] labels = {"Path to nuclei", "Template default save path", "Template author"};
        for (int index = 1; index <= labels.length; index++) {
            final JLabel jLabel = new JLabel(labels[index - 1]);
            final GridBagConstraints nucleiLabelConstraints = createLabelConstraints(index);
            topPanel.add(jLabel, nucleiLabelConstraints);
        }

        int gridY = 0;
        final JTextField nucleiPathTextField = new JTextField();
        final GridBagConstraints nucleiPathConstraints = createTextFieldConstraints(nucleiPathTextField, ++gridY);
        topPanel.add(nucleiPathTextField, nucleiPathConstraints);

        final JTextField templatePathTextField = new JTextField();
        final GridBagConstraints templatePathConstraints = createTextFieldConstraints(templatePathTextField, ++gridY);
        topPanel.add(templatePathTextField, templatePathConstraints);

        final JTextField authorTextField = new JTextField();
        final GridBagConstraints authorFieldConstraints = createTextFieldConstraints(authorTextField, ++gridY);
        topPanel.add(authorTextField, authorFieldConstraints);

        this.valueTextFieldMap = Map.ofEntries(Map.entry(NUCLEI_PATH_VARIABLE, nucleiPathTextField),
                                               Map.entry(TEMPLATE_PATH_VARIABLE, templatePathTextField),
                                               Map.entry(AUTHOR_VARIABLE, authorTextField));

        return topPanel;
    }

    private void loadSavedFieldValues() {
        this.valueTextFieldMap.forEach((k, v) -> {
            if (this.callbacks != null) {
                final String savedValue = this.callbacks.loadExtensionSetting(k);
                if (savedValue != null) {
                    v.setText(savedValue);
                }
            }
        });
        setButtonsVisible(false);
    }

    private GridBagConstraints createLabelConstraints(int gridY) {
        final GridBagConstraints nucleiLabelConstraints = new GridBagConstraints();
        nucleiLabelConstraints.gridx = 0;
        nucleiLabelConstraints.gridy = gridY;
        nucleiLabelConstraints.weightx = 0.1;
        nucleiLabelConstraints.fill = GridBagConstraints.NONE;
        nucleiLabelConstraints.anchor = GridBagConstraints.LINE_START;
        nucleiLabelConstraints.insets = new Insets(10, 10, 10, 0);
        return nucleiLabelConstraints;
    }

    private GridBagConstraints createTextFieldConstraints(JTextField textField, int gridY) {
        textField.setPreferredSize(new Dimension(600, 30));

        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                setButtonsVisible(true);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                setButtonsVisible(true);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                setButtonsVisible(true);
            }
        });

        final GridBagConstraints authorFieldConstraints = new GridBagConstraints();
        authorFieldConstraints.gridx = 1;
        authorFieldConstraints.gridy = gridY;
        authorFieldConstraints.gridwidth = 2;
        authorFieldConstraints.weightx = 0.9;
        authorFieldConstraints.insets = new Insets(10, 0, 10, 10);
        authorFieldConstraints.anchor = GridBagConstraints.LINE_START;
        return authorFieldConstraints;
    }

    private void setButtonsVisible(boolean visibility) {
        if (saveButton.isVisible() != visibility) {
            this.saveButton.setVisible(visibility);
            this.cancelButton.setVisible(visibility);
        }
    }

    public static void main(String[] args) {
        final JFrame frame = new JFrame("Test the Settings Panel");
        frame.setLayout(new GridLayout());
        frame.add(new SettingsPanel());
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.pack();
    }
}
