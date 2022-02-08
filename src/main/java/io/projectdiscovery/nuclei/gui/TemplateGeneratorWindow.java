package io.projectdiscovery.nuclei.gui;

import burp.IBurpExtenderCallbacks;
import io.projectdiscovery.nuclei.gui.editor.NucleiTokenMaker;
import io.projectdiscovery.nuclei.gui.editor.NucleiTokenMakerFactory;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.Utils;
import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.autocomplete.BasicCompletion;
import org.fife.ui.autocomplete.DefaultCompletionProvider;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public class TemplateGeneratorWindow extends JFrame {

    private JTextArea templateEditor;
    private JTextField commandLineField;
    private AnsiColorTextPane outputPane;

    private final IBurpExtenderCallbacks callbacks;
    private Path templatePath;
    private final Path nucleiPath;
    private final Map<String, String> yamlFieldDescriptionMap;

    public TemplateGeneratorWindow(Path nucleiPath, URL targetUrl, String templateYaml, Map<String, String> yamlFieldDescriptionMap) {
        this(nucleiPath, targetUrl, templateYaml, yamlFieldDescriptionMap, null);
    }

    public TemplateGeneratorWindow(Path nucleiPath, URL targetUrl, String templateYaml, Map<String, String> yamlFieldDescriptionMap, IBurpExtenderCallbacks callbacks) {
        super("Nuclei Template Generator");
        this.setLayout(new GridBagLayout());

        this.callbacks = callbacks;
        this.yamlFieldDescriptionMap = yamlFieldDescriptionMap;
        this.nucleiPath = nucleiPath;

        setKeyboardShortcuts();

        final String command = createCommand(nucleiPath, targetUrl);
        cleanupOnClose();

        final Container contentPane = this.getContentPane();
        createControlPanel(contentPane, command);
        createSplitPane(contentPane, templateYaml);

        this.setJMenuBar(new MenuHelper(this::logError).createMenuBar());
        this.setLocationRelativeTo(null); // center of the screen
        this.setPreferredSize(new Dimension(800, 600));
        this.setMinimumSize(this.getSize()); // TODO this is platform dependent, custom logic is needed to enforce it
        this.setVisible(true);
        this.pack();
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

    private void cleanupOnClose() {
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                try {
                    if (TemplateGeneratorWindow.this.templatePath.startsWith(getTempPath())) {
                        Files.deleteIfExists(TemplateGeneratorWindow.this.templatePath);
                    }
                } catch (IOException ex) {
                    logError(String.format("Could not delete temporary file: %s", TemplateGeneratorWindow.this.templatePath));
                    logError(ex.getMessage());
                }

                super.windowClosing(e);
            }
        });
    }

    private String createCommand(Path nucleiPath, URL targetUrl) {
        try {
            this.templatePath = Files.createTempFile("nuclei", ".yaml");
        } catch (IOException e) {
            logError("Could not create temporary file: " + e.getMessage());
        }

        return String.format("%s -v -t %s -u %s",
                             wrapWithQuotesIfNecessary(nucleiPath.toString()),
                             wrapWithQuotesIfNecessary(this.templatePath.toString()),
                             wrapWithQuotesIfNecessary(targetUrl.toString()));
    }

    private String wrapWithQuotesIfNecessary(String input) {
        return input.contains(" ") ? String.format("\"%s\"", input)
                                   : input;
    }

    private void setKeyboardShortcuts() {
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK), new CloseAction(this));
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK), this::executeButtonClick);
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK), () -> this.commandLineField.requestFocus());
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), () -> this.templateEditor.requestFocus());
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), this::saveTemplateToFile);
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0), () -> MenuHelper.openDocumentationLink(this::logError));
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_PLUS, InputEvent.CTRL_DOWN_MASK), () -> {
            deriveFont(this.outputPane, size -> ++size);
            deriveFont(this.templateEditor, size -> ++size);
        });
        setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK), () -> {
            deriveFont(this.outputPane, size -> --size);
            deriveFont(this.templateEditor, size -> --size);
        });
    }

    private void deriveFont(Component component, Function<Integer, Integer> fontSizeModifier) {
        final Font font = component.getFont();
        final int fontSize = font.getSize();
        component.setFont(font.deriveFont((float) fontSizeModifier.apply(fontSize)));
    }

    private void setKeyboardShortcut(KeyStroke keyStroke, Action action) {
        final InputMap frameInputMap = this.rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        final ActionMap frameActionMap = this.rootPane.getActionMap();

        final String shortcutKey = keyStroke.toString();
        frameInputMap.put(keyStroke, shortcutKey);

        frameActionMap.put(shortcutKey, action);
    }

    private void setKeyboardShortcut(KeyStroke keyStroke, Runnable actionPerformed) {
        setKeyboardShortcut(keyStroke, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                actionPerformed.run();
            }
        });
    }

    private static class CloseAction extends AbstractAction {
        private final JFrame frame;

        public CloseAction(JFrame frame) {
            this.frame = frame;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            this.frame.dispatchEvent(new WindowEvent(this.frame, WindowEvent.WINDOW_CLOSING));
        }
    }

    private Component createOutputPane() {
        this.outputPane = new AnsiColorTextPane(this::logError);
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
                logError(e.getMessage());
            }
        }

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
        if (this.callbacks != null) {
            // TODO https://github.com/bobbylight/RSyntaxTextArea/issues/269
            JTextComponent.removeKeymap("RTextAreaKeymap");
            UIManager.put("RSyntaxTextAreaUI.actionMap", null);
            UIManager.put("RSyntaxTextAreaUI.inputMap", null);
            UIManager.put("RTextAreaUI.actionMap", null);
            UIManager.put("RTextAreaUI.inputMap", null);
        }

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
        textEditor.setFont(textEditor.getFont().deriveFont(SettingsPanel.FONT_SIZE));

        setupAutoCompletion(textEditor);

        return textEditor;
    }

    private void createControlPanel(Container contentPane, String command) {
        final JPanel topPanel = new JPanel();
        topPanel.setPreferredSize(new Dimension(200, 50));
        topPanel.setLayout(new GridBagLayout());

        final FilterableJComboBox filterableJComboBox = new FilterableJComboBox(command);
        filterableJComboBox.setPreferredSize(new Dimension(200, 25));

        final JTextField textField = filterableJComboBox.getTextField();
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

    private void saveTemplateToFile() {
        final Path targetTemplatePath = this.callbacks == null ? getTempPath() : Paths.get(this.callbacks.loadExtensionSetting(SettingsPanel.TEMPLATE_PATH_SETTING_NAME));

        final String yamlTemplate = this.templateEditor.getText();
        final Map<?, ?> parsedYaml = new Yaml().loadAs(yamlTemplate, Map.class);
        if (parsedYaml == null) {
            JOptionPane.showMessageDialog(this, "Invalid template", "Template error", JOptionPane.ERROR_MESSAGE);
        } else {
            final String templateId = (String) parsedYaml.get("id"); // TODO it would be nicer to deserialize to Template.class and use the getter for the id
            if (Utils.isBlank(templateId)) {
                JOptionPane.showMessageDialog(this, "Missing mandatory template id!", "Template error", JOptionPane.ERROR_MESSAGE);
            } else {
                final Path generatedFilePath = targetTemplatePath.resolve(templateId + ".yaml");

                final JFileChooser fileChooser = new JFileChooser(generatedFilePath.toFile()) {
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
                fileChooser.setSelectedFile(generatedFilePath.toFile());
                final int option = fileChooser.showSaveDialog(this);

                if (option == JFileChooser.APPROVE_OPTION) {
                    final File userSelectedFile = fileChooser.getSelectedFile();
                    final boolean ok = Utils.writeToFile(yamlTemplate, userSelectedFile.toPath(), this::logError);
                    if (ok) {
                        final String command = this.commandLineField.getText();
                        if (!Utils.isBlank(command) && command.contains(Utils.NUCLEI_BASE_BINARY_NAME)) {
                            this.templatePath = userSelectedFile.toPath();
                            this.commandLineField.setText(Utils.replaceTemplatePathInCommand(command, userSelectedFile.toString()));
                        }
                    } else {
                        JOptionPane.showMessageDialog(this, "Error while writing file to: " + userSelectedFile, "File write error", JOptionPane.ERROR_MESSAGE);
                    }
                    log("Generated nuclei template saved to: " + userSelectedFile);
                }
            }
        }
    }

    private Path getTempPath() {
        return Paths.get(System.getProperty("java.io.tmpdir"));
    }

    private void executeButtonClick() {
        String command = this.commandLineField.getText();

        if (!Utils.isBlank(command)) {
            Utils.writeToFile(this.templateEditor.getText(), this.templatePath, this::logError);

            this.outputPane.setText(null);

            final boolean noColor = command.contains(" -nc") || command.contains(" -no-color");

            if (command.startsWith(Utils.NUCLEI_BASE_BINARY_NAME)) {
                command = command.replaceFirst("nuclei(\\.exe)?", this.nucleiPath.toString());
            }

            Utils.executeCommand(command,
                                 bufferedReader -> bufferedReader.lines()
                                                                 .map(line -> line + "\n")
                                                                 .forEach(line -> SwingUtilities.invokeLater(() -> {
                                                                     this.outputPane.appendText(line, noColor);
                                                                     this.outputPane.repaint();
                                                                 })),
                                 exitCode -> SwingUtilities.invokeLater(() -> this.outputPane.appendText("\nThe process exited with code " + exitCode)),
                                 this::logError);
        }
    }

    private void log(String message) {
        System.out.println(message);

        if (Objects.nonNull(this.callbacks)) {
            this.callbacks.printOutput(message);
        }
    }

    private void logError(String message) {
        System.err.println(message);

        if (Objects.nonNull(this.callbacks)) {
            this.callbacks.printError(message);
        }
    }

    public static void main(String[] args) throws Exception {
        final URL url = new URL("http://localhost:8081");

        final String template = "id: template-id\n" +
                                "info:\n" +
                                "  author: forgedhallpass\n" +
                                "  name: Template Name\n" +
                                "  severity: info\n" +
                                "requests:\n" +
                                "  - raw:\n" +
                                "    - |\n" +
                                "      GET / HTTP/1.1\n" +
                                "      Host: {{Hostname}}\n" +
                                "      Accept: */*\n" +
                                "    matchers:\n" +
                                "    - type: status\n" +
                                "      status:\n" +
                                "      - 200\n";

        final TemplateGeneratorWindow templateGeneratorWindow = new TemplateGeneratorWindow(Paths.get("nuclei"), url, template, SchemaUtils.retrieveYamlFieldWithDescriptions());
        templateGeneratorWindow.setDefaultCloseOperation(EXIT_ON_CLOSE);
    }
}
