package io.projectdiscovery.nuclei.gui;

import io.projectdiscovery.cve.CveInfo;
import io.projectdiscovery.cve.nist.service.CveInfoRetriever;
import io.projectdiscovery.nuclei.gui.editor.NucleiTokenMaker;
import io.projectdiscovery.nuclei.gui.editor.NucleiTokenMakerFactory;
import io.projectdiscovery.nuclei.model.Info;
import io.projectdiscovery.nuclei.model.Template;
import io.projectdiscovery.nuclei.util.NucleiUtils;
import io.projectdiscovery.nuclei.yaml.YamlUtil;
import io.projectdiscovery.utils.CommandLineUtils;
import io.projectdiscovery.utils.ExecutionResult;
import io.projectdiscovery.utils.Utils;
import io.projectdiscovery.utils.gui.SwingUtils;
import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.autocomplete.BasicCompletion;
import org.fife.ui.autocomplete.DefaultCompletionProvider;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.yaml.snakeyaml.error.YAMLException;

import javax.swing.*;
import javax.swing.event.MouseInputAdapter;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.function.Function;

public final class TemplateGeneratorTab extends JPanel {

    private static Map<String, String> CLI_ARGUMENT_MAP;

    private final NucleiGeneratorSettings nucleiGeneratorSettings;
    private final Path nucleiPath;
    private final Map<String, String> yamlFieldDescriptionMap;

    private JTextArea templateEditor;
    private JTextField commandLineField;
    private AnsiColorTextPane outputPane;

    private Path templatePath;

    public TemplateGeneratorTab(NucleiGeneratorSettings nucleiGeneratorSettings) {
        this(null, nucleiGeneratorSettings);
    }

    public TemplateGeneratorTab(String name, NucleiGeneratorSettings nucleiGeneratorSettings) {
        super();
        this.setLayout(new GridBagLayout());

        if (name != null) {
            this.setName(name);
        }

        this.nucleiPath = nucleiGeneratorSettings.getNucleiPath();
        this.yamlFieldDescriptionMap = nucleiGeneratorSettings.getYamlFieldDescriptionMap();
        this.nucleiGeneratorSettings = nucleiGeneratorSettings;

        setKeyboardShortcuts();

        final String command = createCommand(this.nucleiPath, nucleiGeneratorSettings.getTargetUrl());

        createControlPanel(this, command);
        createSplitPane(this, nucleiGeneratorSettings.getTemplateYaml());

        initializeNucleiCliArgumentMap(nucleiGeneratorSettings);
    }

    public Optional<Template> getTemplate() {
        return parseTemplate(this.templateEditor.getText());
    }

    public void setTemplate(Template template) {
        this.templateEditor.setText(YamlUtil.dump(template));
    }

    void cleanup() {
        try {
            if (this.templatePath.startsWith(Utils.getTempPath())) {
                if (Files.deleteIfExists(this.templatePath)) {
                    this.nucleiGeneratorSettings.log(String.format("Deleted temporary template at '%s'.", this.templatePath));
                }
            }
        } catch (IOException ex) {
            this.nucleiGeneratorSettings.logError(String.format("Could not delete temporary file: '%s'.", this.templatePath));
            this.nucleiGeneratorSettings.logError(ex.getMessage());
        }
    }

    private void createSplitPane(Container contentPane, String templateYaml) {
        final JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createTextEditor(templateYaml), createOutputPane());
        splitPane.setOneTouchExpandable(true);
        splitPane.setResizeWeight(0.5);

        final GridBagConstraints outputConstraints = new GridBagConstraints();
        outputConstraints.gridx = 0;
        outputConstraints.gridy = 1;
        outputConstraints.weightx = 1;
        outputConstraints.weighty = 0.9;
        outputConstraints.fill = GridBagConstraints.BOTH;
        contentPane.add(splitPane, outputConstraints);
    }

    private String createCommand(Path nucleiPath, URL targetUrl) {
        try {
            this.templatePath = Files.createTempFile("nuclei", ".yaml");
        } catch (IOException e) {
            this.nucleiGeneratorSettings.logError(String.format("Could not create temporary file: '%s'.", e.getMessage()));
        }

        return String.format("%s -v -t %s -u %s",
                wrapWithQuotesIfNecessary(nucleiPath.toString()),
                wrapWithQuotesIfNecessary(this.templatePath.toString()),
                wrapWithQuotesIfNecessary(targetUrl.toString()));
    }

    private static String wrapWithQuotesIfNecessary(String input) {
        return input.contains(" ") ? String.format("\"%s\"", input)
                : input;
    }

    private void setKeyboardShortcuts() {
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK), this::executeButtonClick);
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK), () -> this.commandLineField.requestFocus());
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), () -> this.templateEditor.requestFocus());
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), this::saveTemplateToFile);
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_PLUS, InputEvent.CTRL_DOWN_MASK), () -> deriveFont(Arrays.asList(this.templateEditor, this.outputPane), size -> ++size));
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), () -> deriveFont(Arrays.asList(this.templateEditor, this.outputPane), size -> ++size));
        SwingUtils.setKeyboardShortcut(this, KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK), () -> deriveFont(Arrays.asList(this.templateEditor, this.outputPane), size -> --size));
    }

    private void deriveFont(Collection<Component> components, Function<Integer, Integer> fontSizeModifier) {
        if (components.isEmpty()) {
            throw new IllegalArgumentException("Component list must not be empty when modifying the font size!");
        } else {
            // force the same font size of all given components
            final int currentFontSize = components.iterator().next().getFont().getSize();
            final Integer newFontSize = fontSizeModifier.apply(currentFontSize);

            if (newFontSize > 8 && newFontSize < 30) {
                components.forEach(component -> {
                    final Font font = component.getFont();
                    component.setFont(font.deriveFont(newFontSize.floatValue()));
                });

                this.nucleiGeneratorSettings.saveFontSize(newFontSize);
            }
        }
    }

    private Component createOutputPane() {
        this.outputPane = new AnsiColorTextPane(this.nucleiGeneratorSettings.getFontSize(), this.nucleiGeneratorSettings::logError);
        this.outputPane.setEditable(false);
        this.outputPane.setVisible(true);
        this.outputPane.setAutoscrolls(true);

        final JScrollPane scrollPane = createScrollPane(this.outputPane, "Output");
        scrollPane.setVisible(true);

        return scrollPane;
    }

    private JScrollPane createScrollPane(Component component, String paneTitle) {
        final JScrollPane editorScrollPane = new JScrollPane(component, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        editorScrollPane.setBorder(BorderFactory.createTitledBorder(paneTitle));
        return editorScrollPane;
    }

    private Component createTextEditor(String templateYaml) {
        final RSyntaxTextArea textEditor = createSmartTextEditor(templateYaml);

        if (UIManager.getLookAndFeel().getID().toLowerCase().contains("dark")) {
            final InputStream resourceAsStream = this.getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml");
            final Theme theme;
            try {
                theme = Theme.load(resourceAsStream);
                theme.apply(textEditor);
            } catch (IOException e) {
                this.nucleiGeneratorSettings.logError(e.getMessage());
            }
        }

        textEditor.setFont(textEditor.getFont().deriveFont(this.nucleiGeneratorSettings.getFontSize().floatValue()));
        this.templateEditor = textEditor;

        final RTextScrollPane scrollPane = new RTextScrollPane(textEditor, true);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Template"));
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        return scrollPane;
    }

    private void setupAutoCompletion(RSyntaxTextArea textEditor) {
        if (this.yamlFieldDescriptionMap != null) {
            final DefaultCompletionProvider defaultCompletionProvider = new DefaultCompletionProvider();
            defaultCompletionProvider.setAutoActivationRules(true, null);

            this.yamlFieldDescriptionMap.forEach((key, value) -> defaultCompletionProvider.addCompletion(new BasicCompletion(defaultCompletionProvider, key, value)));

            final AutoCompletion autoCompletion = new AutoCompletion(defaultCompletionProvider);
//            autoCompletion.setShowDescWindow(true); TODO point to or open remote documentation
            autoCompletion.setAutoCompleteEnabled(true);
            autoCompletion.setAutoActivationEnabled(true);
            autoCompletion.setAutoCompleteSingleChoices(false);
            autoCompletion.setAutoActivationDelay(500);

            autoCompletion.install(textEditor);
        }
    }

    private RSyntaxTextArea createSmartTextEditor(String templateYaml) {
        // TODO https://github.com/bobbylight/RSyntaxTextArea/issues/269
        JTextComponent.removeKeymap("RTextAreaKeymap");
        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);

        final boolean experimental = true; // TODO move to settings
        final RSyntaxTextArea textEditor;
        if (experimental) {
            final AbstractTokenMakerFactory nucleiTokenMakerFactory = new NucleiTokenMakerFactory(this.yamlFieldDescriptionMap.keySet());
            textEditor = new RSyntaxTextArea(new RSyntaxDocument(nucleiTokenMakerFactory, NucleiTokenMaker.NUCLEI_YAML_SYNTAX));
        } else {
            textEditor = new RSyntaxTextArea();
            textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_YAML);
        }

        textEditor.setEditable(true);
        textEditor.setAntiAliasingEnabled(true);
        textEditor.setTabsEmulated(true);
        textEditor.setAutoIndentEnabled(true);
        textEditor.setTabSize(2);
        textEditor.setText(templateYaml);
        textEditor.getPopupMenu().add(createTemplateEditorMenuItems());

        setupAutoCompletion(textEditor);

        // Add mouse listener for Ctrl + Click
        textEditor.addMouseListener(new MouseInputAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1 && e.isControlDown()) { // Trigger on Ctrl + Click
                    int offset = textEditor.viewToModel2D(e.getPoint());
                    String url = getUrlAtOffset(textEditor, offset);
                    if (url != null) {
                        try {
                            SwingUtils.openWebPage(new URI(url).toURL());
                        } catch (IOException | URISyntaxException ex) {
                            ex.printStackTrace();
                        }
                    }
                }
            }
        });

        return textEditor;
    }

    private String getUrlAtOffset(RSyntaxTextArea textEditor, int offset) {
        try {
            int start = offset;
            int end = offset;
            while (start > 0 && !Character.isWhitespace(textEditor.getText(start - 1, 1).charAt(0))) {
                start--;
            }
            while (end < textEditor.getDocument().getLength() && !Character.isWhitespace(textEditor.getText(end, 1).charAt(0))) {
                end++;
            }

            String potentialUrl = textEditor.getText(start, end - start);
            if (potentialUrl.startsWith("http://") || potentialUrl.startsWith("https://")) {
                return potentialUrl;
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
        return null;
    }

    private JMenu createTemplateEditorMenuItems() {
        final JMenu templateMenu = new JMenu("Add");
        templateMenu.add(createTemplateEditorClassificationMenu());
        return templateMenu;
    }

    private JMenu createTemplateEditorClassificationMenu() {
        final JMenu classificationMenu = new JMenu("Classification");

        classificationMenu.add(createEmptyClassificationMenuItem());
        classificationMenu.add(createCveClassificationMenuItem());

        return classificationMenu;
    }

    private JMenuItem createEmptyClassificationMenuItem() {
        final JMenuItem emptyClassificationMenuItem = new JMenuItem("Empty");
        emptyClassificationMenuItem.addActionListener(e -> modifyTemplate(template -> template.getInfo().setClassification(new Info.Classification())));
        return emptyClassificationMenuItem;
    }

    private JMenuItem createCveClassificationMenuItem() {
        final JMenuItem cveMenuItem = new JMenuItem("CVE");

        cveMenuItem.addActionListener(e -> modifyTemplate(template -> {
            final String cveId = JOptionPane.showInputDialog("Enter CVE ID (e.g. CVE-2021-1234):", "CVE-");

            if (cveId != null) {
                if (cveId.matches("(?i)cve-\\d{4}-\\d{4,7}")) {
                    final Optional<CveInfo> cveInfo = CveInfoRetriever.getCveInfo(cveId);
                    cveInfo.map(cve -> {
                        template.setId(cveId);
                        final Info.Classification classification = new Info.Classification(cve.getId(), cve.getCvssMetrics(), cve.getCvssScore(), cve.getCweIds());
                        final Info templateInfo = template.getInfo();
                        templateInfo.setSeverity(cve.getSeverity());
                        templateInfo.setDescriptionIfDefault(cve.getDescription());
                        templateInfo.setReference(cve.getReferences());
                        templateInfo.setClassification(classification);
                        templateInfo.setTags(List.of("cve", cveId.substring(0, "cve-1234".length()).replace("-", "").toLowerCase())); // add cve and cveYEAR tags
                        return template;
                    }).orElseGet(() -> {
                        JOptionPane.showMessageDialog(null, "Could not find CVE information. Please fill it manually.", "Could not find CVE information.", JOptionPane.WARNING_MESSAGE);
                        template.getInfo().setClassification(new Info.Classification());
                        return template;
                    });
                } else {
                    JOptionPane.showMessageDialog(null, "Invalid CVE ID. Please use the CVE-2021-1234 format.", "Invalid CVE ID", JOptionPane.ERROR_MESSAGE);
                }
            }
        }));

        return cveMenuItem;
    }

    private void modifyTemplate(Consumer<Template> templateConsumer) {
        final String currentTemplate = this.templateEditor.getText();
        try {
            final Template template = YamlUtil.load(currentTemplate, Template.class);
            templateConsumer.accept(template);
            this.templateEditor.setText(YamlUtil.dump(template));
        } catch (YAMLException yamlException) {
            JOptionPane.showMessageDialog(null, "Please fix the errors and try again:\n" + yamlException.getMessage(), "Invalid template", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createControlPanel(Container contentPane, String command) {
        final JPanel topPanel = new JPanel();
        topPanel.setPreferredSize(new Dimension(200, 50));
        topPanel.setLayout(new GridBagLayout());

        final FilterableJComboBox filterableJComboBox = new FilterableJComboBox(command);
        filterableJComboBox.setPreferredSize(new Dimension(200, 25));

        final JTextField textField = filterableJComboBox.getTextField();

        SwingUtils.setKeyboardShortcut(textField, KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK), () -> {
            if (CLI_ARGUMENT_MAP != null && !CLI_ARGUMENT_MAP.isEmpty()) {
                final FilterableListWindow cliArgumentHelperWindow = new FilterableListWindow(CLI_ARGUMENT_MAP, selectedValue -> {
                    final String currentCommand = textField.getText();
                    textField.setText(currentCommand + ' ' + selectedValue);
                });
                final Container commandLineComboBox = this.commandLineField.getParent();
                final Point commandLineComboLocation = commandLineComboBox.getLocationOnScreen();
                final Dimension commandLineComboSize = commandLineComboBox.getSize();
                cliArgumentHelperWindow.setSize((int) commandLineComboSize.getWidth(), (int) cliArgumentHelperWindow.getSize().getHeight());
                cliArgumentHelperWindow.setLocation((int) commandLineComboLocation.getX(), (int) (commandLineComboLocation.getY() + commandLineComboSize.getHeight()));
            }
        });

        textField.addActionListener(e -> executeButtonClick());
        this.commandLineField = textField;

        final GridBagConstraints commandsComboBoxConstraints = new GridBagConstraints();
        commandsComboBoxConstraints.gridx = 0;
        commandsComboBoxConstraints.gridy = 0;
        commandsComboBoxConstraints.weightx = 1.0;
        commandsComboBoxConstraints.gridheight = 1;
        commandsComboBoxConstraints.insets = new Insets(0, 5, 0, 5);
        commandsComboBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        topPanel.add(filterableJComboBox, commandsComboBoxConstraints);

        final JButton executeBtn = new JButton("Execute");
        executeBtn.setMnemonic(KeyEvent.VK_E);
        executeBtn.addActionListener(e -> executeButtonClick());

        final GridBagConstraints executeBtnConstraints = new GridBagConstraints();
        executeBtnConstraints.gridx = 1;
        executeBtnConstraints.gridy = 0;
        executeBtnConstraints.gridheight = 1;
        executeBtnConstraints.insets = new Insets(0, 5, 0, 5);
        topPanel.add(executeBtn, executeBtnConstraints);

        final JButton clipboardBtn = new JButton("Copy Template to Clipboard");
        clipboardBtn.setMnemonic(KeyEvent.VK_C);
        clipboardBtn.addActionListener(e -> {
            final String templateYaml = this.templateEditor.getText();
            final Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(templateYaml), null);
        });

        final GridBagConstraints clipBoardButtonConstraints = new GridBagConstraints();
        clipBoardButtonConstraints.gridx = 2;
        clipBoardButtonConstraints.gridy = 0;
        clipBoardButtonConstraints.gridheight = 1;
        clipBoardButtonConstraints.insets = new Insets(0, 5, 0, 5);
        topPanel.add(clipboardBtn, clipBoardButtonConstraints);

        final JButton saveButton = new JButton("Save");
        saveButton.setMnemonic(KeyEvent.VK_S);
        saveButton.addActionListener(e -> saveTemplateToFile());

        final GridBagConstraints saveButtonConstraints = new GridBagConstraints();
        saveButtonConstraints.gridx = 3;
        saveButtonConstraints.gridy = 0;
        saveButtonConstraints.gridheight = 1;
        saveButtonConstraints.insets = new Insets(0, 5, 0, 5);
        topPanel.add(saveButton, saveButtonConstraints);

        final GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.weightx = 1;
        panelConstraints.gridwidth = 2;
        panelConstraints.fill = GridBagConstraints.BOTH;

        contentPane.add(topPanel, panelConstraints);
    }

    private static void initializeNucleiCliArgumentMap(NucleiGeneratorSettings generalSettings) {
        if (CLI_ARGUMENT_MAP == null) {
            try {
                final Path nucleiPath = generalSettings.getNucleiPath();
                if (nucleiPath != null) {
                    final ExecutionResult<Map<String, String>> executionResult = CommandLineUtils.executeCommand(new String[]{nucleiPath.toString(), "-help"}, NucleiUtils::getCliArguments);
                    if (executionResult.isSuccessful()) {
                        CLI_ARGUMENT_MAP = executionResult.getResult();
                    }
                }
            } catch (ExecutionException e) {
                generalSettings.logError(String.format("Error while trying to retrieve the nuclei help menu. CLI argument helper will be disabled: '%s'.", e.getMessage()));
            }
        }
    }

    private void saveTemplateToFile() {
        final Path targetTemplatePath = this.nucleiGeneratorSettings.getTemplatePath();
        final String yamlTemplate = this.templateEditor.getText();
        parseTemplate(yamlTemplate).ifPresent(template -> {
            final String templateId = template.getId();
            if (Utils.isBlank(templateId)) {
                JOptionPane.showMessageDialog(this, "Missing mandatory template id!", "Template error", JOptionPane.ERROR_MESSAGE);
            } else {
                final Path generatedFilePath = targetTemplatePath.resolve(templateId + ".yaml");
                saveTemplateToFile(generatedFilePath, yamlTemplate);
            }
        });
    }

    private Optional<Template> parseTemplate(String yamlTemplate) {
        Optional<Template> result = Optional.empty();
        try {
            final Template template = YamlUtil.load(yamlTemplate, Template.class);

            if (template == null) {
                JOptionPane.showMessageDialog(this, "Invalid template", "Invalid template", JOptionPane.ERROR_MESSAGE);
            } else {
                result = Optional.of(template);
            }
        } catch (YAMLException e) {
            JOptionPane.showMessageDialog(this, "Please fix the errors and try again:\n" + e.getMessage(), "Invalid template", JOptionPane.ERROR_MESSAGE);
        }

        return result;
    }

    private void saveTemplateToFile(Path generatedFilePath, String yamlTemplate) {
        final JFileChooser fileChooser = createFileChooser(generatedFilePath);
        fileChooser.setSelectedFile(generatedFilePath.toFile());
        final int option = fileChooser.showSaveDialog(this);

        if (option == JFileChooser.APPROVE_OPTION) {
            final File userSelectedFile = fileChooser.getSelectedFile();
            final boolean ok = Utils.writeToFile(yamlTemplate, userSelectedFile.toPath(), this.nucleiGeneratorSettings::logError);
            if (ok) {
                final String command = this.commandLineField.getText();
                if (!Utils.isBlank(command) && command.contains(NucleiUtils.NUCLEI_BASE_BINARY_NAME)) {
                    this.templatePath = userSelectedFile.toPath();
                    this.commandLineField.setText(NucleiUtils.replaceTemplatePathInCommand(command, userSelectedFile.toString()));
                }
            } else {
                JOptionPane.showMessageDialog(this, String.format("Error while writing file to: '%s'.", userSelectedFile), "File write error", JOptionPane.ERROR_MESSAGE);
            }
            this.nucleiGeneratorSettings.log(String.format("Generated nuclei template saved to: '%s'.", userSelectedFile));
        }
    }

    private JFileChooser createFileChooser(Path generatedFilePath) {
        return new JFileChooser(generatedFilePath.toFile()) {
            @Override
            public void approveSelection() {
                final File selectedFile = getSelectedFile();
                if (selectedFile.exists() && getDialogType() == SAVE_DIALOG) {
                    final int result = JOptionPane.showConfirmDialog(this, "The selected file already exists. Do you want to overwrite it?",
                            "Overwrite existing file?",
                            JOptionPane.YES_NO_CANCEL_OPTION);
                    switch (result) {
                        case JOptionPane.YES_OPTION:
                            super.approveSelection();
                            return;
                        case JOptionPane.CANCEL_OPTION:
                            cancelSelection();
                            return;
                        case JOptionPane.CLOSED_OPTION:
                        case JOptionPane.NO_OPTION:
                        default:
                            return;
                    }
                }
                super.approveSelection();
            }
        };
    }

    private void executeButtonClick() {
        String command = this.commandLineField.getText();

        if (!Utils.isBlank(command)) {
            Utils.writeToFile(this.templateEditor.getText(), this.templatePath, this.nucleiGeneratorSettings::logError);

            this.outputPane.setText(null);

            final boolean noColor = command.contains(" -nc") || command.contains(" -no-color");

            if (command.startsWith(NucleiUtils.NUCLEI_BASE_BINARY_NAME)) {
                command = command.replaceFirst("nuclei(\\.exe)?", this.nucleiPath.toString());
            }

            CommandLineUtils.asyncExecuteCommand(command,
                    bufferedReader -> bufferedReader.lines()
                            .map(line -> line + "\n")
                            .forEach(line -> SwingUtilities.invokeLater(() -> {
                                this.outputPane.appendText(line, noColor);
                                this.outputPane.repaint();
                            })),
                    exitCode -> SwingUtilities.invokeLater(() -> this.outputPane.appendText("\nThe process exited with code " + exitCode)),
                    this.nucleiGeneratorSettings::logError);
        }
    }
}