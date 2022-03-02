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
import io.projectdiscovery.utils.Utils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.Map;
import java.util.Optional;

public class SettingsPanel extends JPanel {

    public static final String NUCLEI_PATH_SETTING_NAME = "nucleiPath";
    public static final String TEMPLATE_PATH_SETTING_NAME = "templatePath";
    public static final String AUTHOR_SETTING_NAME = "author";
    public static final String FONT_SIZE_SETTING_NAME = "fontSize";
    public static final int DEFAULT_FONT_SIZE = 14;

    private final GeneralSettings settings;
    private JButton cancelButton;
    private JButton saveButton;
    private Map<String, JTextField> valueTextFieldMap;

    public SettingsPanel(GeneralSettings generalSettings) {
        this.settings = generalSettings;

        this.setLayout(new GridBagLayout());

        final JPanel formPanel = createFormPanel();
        final GridBagConstraints formPanelConstraints = new GridBagConstraints();
        formPanelConstraints.gridx = 0;
        formPanelConstraints.gridy = 0;
        formPanelConstraints.weightx = 0.2;
        formPanelConstraints.weighty = 0.95;
        formPanelConstraints.fill = GridBagConstraints.BOTH;

        this.add(formPanel, formPanelConstraints);

        final JPanel rightPanel = new JPanel();
        final GridBagConstraints rightPanelConstraints = new GridBagConstraints();
        rightPanelConstraints.gridx = 1;
        rightPanelConstraints.gridy = 0;
        rightPanelConstraints.weightx = 0.8;
        rightPanelConstraints.weighty = 1;
        rightPanelConstraints.fill = GridBagConstraints.BOTH;

        this.add(rightPanel, rightPanelConstraints);

        loadSavedFieldValues();
    }

    private void saveConfigValues() {
        this.valueTextFieldMap.forEach((k, v) -> this.settings.saveExtensionSetting(k, v.getText()));
        enableButtons(false);
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

        final JPanel middlePanel = new JPanel();
        final GridBagConstraints middlePanelConstraints = new GridBagConstraints();
        middlePanelConstraints.weightx = 1;
        middlePanelConstraints.weighty = 0.6;
        middlePanelConstraints.gridx = 0;
        middlePanelConstraints.gridy = 1;
        middlePanelConstraints.fill = GridBagConstraints.BOTH;

        formPanel.add(middlePanel, middlePanelConstraints);

        return formPanel;
    }

    private JPanel createFormTopPanel() {
        final JPanel topPanel = new JPanel(new GridBagLayout());

        createSettingsHeader(topPanel);

        createLabels(topPanel);

        createTextFields(topPanel);

        createButtons(topPanel);

        addAlignmentBoxes(topPanel);

        return topPanel;
    }

    private void addAlignmentBoxes(JPanel topPanel) {
        // create empty cells on the right, so that the previously created buttons can be centered against the text fields
        for (int i = 0; i <= this.valueTextFieldMap.size() + 1; i++) {
            final Box horizontalBox = Box.createHorizontalBox();
            final GridBagConstraints boxConstraints = new GridBagConstraints();
            boxConstraints.gridx = 3;
            boxConstraints.gridy = i;
            boxConstraints.weightx = 1.2;
            boxConstraints.fill = GridBagConstraints.HORIZONTAL;
            topPanel.add(horizontalBox, boxConstraints);
        }
    }

    private void createTextFields(JPanel topPanel) {
        int gridY = 0;
        final JTextField nucleiPathTextField = new JTextField(); // TODO add dialog window to make the selection more convenient
        final GridBagConstraints nucleiPathConstraints = createTextFieldConstraints(nucleiPathTextField, ++gridY);
        topPanel.add(nucleiPathTextField, nucleiPathConstraints);

        final JTextField templatePathTextField = new JTextField(); // TODO add dialog window to make the selection more convenient
        final GridBagConstraints templatePathConstraints = createTextFieldConstraints(templatePathTextField, ++gridY);
        topPanel.add(templatePathTextField, templatePathConstraints);

        final JTextField authorTextField = new JTextField();
        final GridBagConstraints authorFieldConstraints = createTextFieldConstraints(authorTextField, ++gridY);
        topPanel.add(authorTextField, authorFieldConstraints);

        this.valueTextFieldMap = Map.ofEntries(Map.entry(NUCLEI_PATH_SETTING_NAME, nucleiPathTextField),
                                               Map.entry(TEMPLATE_PATH_SETTING_NAME, templatePathTextField),
                                               Map.entry(AUTHOR_SETTING_NAME, authorTextField));
    }

    private void createButtons(JPanel topPanel) {
        final JPanel buttonPanel = new JPanel(new GridBagLayout());

        this.saveButton = new JButton("Save");
        this.saveButton.setMnemonic(KeyEvent.VK_S);
        final GridBagConstraints saveConstraints = createButtonConstraints(0, 0);
        this.saveButton.addActionListener(e -> saveConfigValues());
        buttonPanel.add(this.saveButton, saveConstraints);

        this.cancelButton = new JButton("Cancel");
        this.cancelButton.setMnemonic(KeyEvent.VK_C);
        this.cancelButton.addActionListener(e -> {
            loadSavedFieldValues();
            enableButtons(false);
        });
        final GridBagConstraints cancelConstraints = createButtonConstraints(1, 5);
        buttonPanel.add(this.cancelButton, cancelConstraints);

        final GridBagConstraints buttonPanelConstraints = new GridBagConstraints();
        buttonPanelConstraints.gridx = 1;
        buttonPanelConstraints.gridwidth = 2;
        buttonPanelConstraints.gridy = 4;
        buttonPanelConstraints.weightx = 0.01;
        buttonPanelConstraints.fill = GridBagConstraints.HORIZONTAL;

        topPanel.add(buttonPanel, buttonPanelConstraints);
    }

    private void createSettingsHeader(Container container) {
        final JLabel heading = new JLabel("Template generator constants");
        heading.setFont(heading.getFont().deriveFont(Font.PLAIN, 18));
        final GridBagConstraints headerConstraints = new GridBagConstraints();
        headerConstraints.gridx = 0;
        headerConstraints.gridwidth = 3;
        headerConstraints.gridy = 0;
        headerConstraints.fill = GridBagConstraints.HORIZONTAL;
        headerConstraints.insets = new Insets(10, 10, 30, 0);
        container.add(heading, headerConstraints);
    }

    private void createLabels(Container container) {
        final String[] labels = {"Path to nuclei", "Template default save path", "Template author"};
        for (int index = 1; index <= labels.length; index++) {
            final JLabel jLabel = new JLabel(labels[index - 1]);
            final GridBagConstraints nucleiLabelConstraints = createLabelConstraints(index);
            container.add(jLabel, nucleiLabelConstraints);
        }
    }

    private GridBagConstraints createButtonConstraints(int gridx, int inset) {
        final GridBagConstraints buttonConstraint = new GridBagConstraints();
        buttonConstraint.gridx = gridx;
        buttonConstraint.gridy = 0;
        buttonConstraint.fill = GridBagConstraints.CENTER;
        buttonConstraint.insets = new Insets(10, inset, 10, 5);
        return buttonConstraint;
    }

    private void loadSavedFieldValues() {
        this.valueTextFieldMap.forEach((configurationName, configurationField) -> {
            final String savedValue = this.settings.loadExtensionSetting(configurationName);
            if (Utils.isBlank(savedValue)) {
                calculateDefaultConfigurationValue(configurationName, configurationField);
            } else {
                configurationField.setText(savedValue);
            }
        });

        enableButtons(false);
    }

    private void calculateDefaultConfigurationValue(String configurationName, JTextField configurationField) {
        try {
            switch (configurationName) {
                case NUCLEI_PATH_SETTING_NAME: {
                    NucleiUtils.calculateNucleiPath().ifPresent(nucleiPath -> configurationField.setText(nucleiPath.toString()));
                    break;
                }
                case TEMPLATE_PATH_SETTING_NAME: {
                    NucleiUtils.detectDefaultTemplatePath().ifPresent(configurationField::setText);
                    break;
                }
                case AUTHOR_SETTING_NAME: {
                    Optional.ofNullable(System.getProperty("user.name")).ifPresent(configurationField::setText);
                    break;
                }
            }

            saveConfigValues();
        } catch (Exception e) {
            this.settings.logError(String.format("Could not load default value(s): '%s'.", e.getMessage()));
        }
    }

    private GridBagConstraints createLabelConstraints(int gridY) {
        final GridBagConstraints nucleiLabelConstraints = new GridBagConstraints();
        nucleiLabelConstraints.gridx = 0;
        nucleiLabelConstraints.gridy = gridY;
        nucleiLabelConstraints.weightx = 0.05;
        nucleiLabelConstraints.anchor = GridBagConstraints.LINE_START;
        nucleiLabelConstraints.insets = new Insets(10, 10, 10, 0);
        return nucleiLabelConstraints;
    }

    private GridBagConstraints createTextFieldConstraints(JTextField textField, int gridY) {
        textField.setPreferredSize(new Dimension(600, 30));

        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                enableButtons(true);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                enableButtons(true);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                enableButtons(true);
            }
        });

        final GridBagConstraints fieldConstraints = new GridBagConstraints();
        fieldConstraints.gridx = 1;
        fieldConstraints.gridy = gridY;
        fieldConstraints.gridwidth = 2;
        fieldConstraints.weightx = 0.5;
        fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
        fieldConstraints.insets = new Insets(10, 0, 10, 0);
        fieldConstraints.anchor = GridBagConstraints.LINE_START;
        return fieldConstraints;
    }

    private void enableButtons(boolean enabled) {
        this.saveButton.setEnabled(enabled);
        this.cancelButton.setEnabled(enabled);
    }

    public static void main(String[] args) {
        final JFrame frame = new JFrame("Test the Settings Panel");
        frame.setLayout(new GridLayout());
        frame.add(new SettingsPanel(new GeneralSettings.Builder().build()));
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.pack();
    }
}
