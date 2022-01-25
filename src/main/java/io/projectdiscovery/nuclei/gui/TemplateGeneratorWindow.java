package io.projectdiscovery.nuclei.gui;

import burp.IBurpExtenderCallbacks;
import io.projectdiscovery.nuclei.util.Utils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

public class TemplateGeneratorWindow extends JFrame {

    private JTextArea templateEditor;
    private JTextField commandLineField;
    private JTextArea outputPanel;

    private final IBurpExtenderCallbacks callbacks;
    private Path temporaryTemplatePath;

    public TemplateGeneratorWindow(URL targetUrl, String templateYaml) {
        this(Paths.get("nuclei"), targetUrl, templateYaml, null);
    }

    public TemplateGeneratorWindow(Path nucleiPath, URL targetUrl, String templateYaml, IBurpExtenderCallbacks callbacks) {
        super("Nuclei Template Generator"); // TODO setIconImage
        this.setLayout(new GridBagLayout());

        this.callbacks = callbacks;

        setKeyboardShortcuts();

        String command = createCommand(targetUrl, nucleiPath);
        cleanupOnClose();

        final Container contentPane = this.getContentPane();
        createControlPanel(contentPane, command);
        createSplitPane(contentPane, templateYaml);

        this.setLocationRelativeTo(null); // center of the screen
        this.setPreferredSize(new Dimension(800, 600));
        this.setMinimumSize(this.getSize()); // TODO this is platform dependent, custom logic is needed to enforce it
        this.setVisible(true);
        this.pack();
    }

    private void createSplitPane(Container contentPane, String templateYaml) {
        final JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createTextEditor(templateYaml), createOutputPanel());
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
                    Files.deleteIfExists(temporaryTemplatePath);
                } catch (IOException ex) {
                    logError(String.format("Could not delete temporary file: %s", temporaryTemplatePath));
                    logError(ex.getMessage());
                }

                super.windowClosing(e);
            }
        });
    }

    private String createCommand(URL targetUrl, Path nucleiPath) {
        try {
            temporaryTemplatePath = Files.createTempFile("nuclei", ".yaml");
        } catch (IOException e) {
            logError("Could not create temporary file: " + e.getMessage());
        }

        // TODO quoting in case of Windows?
        return String.format("%s -nc -v -t %s -u %s", nucleiPath, temporaryTemplatePath, targetUrl);
    }

    private void setKeyboardShortcuts() {
        final InputMap frameInputMap = this.rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        final ActionMap frameActionMap = this.rootPane.getActionMap();

        setCloseWithKeyboardShortcut(frameInputMap, frameActionMap);
        setSubmitTemplateKeyboardShortcut(frameInputMap, frameActionMap);
    }

    private void setSubmitTemplateKeyboardShortcut(InputMap frameInputMap, ActionMap frameActionMap) {
        final String submit = "text-submit";
        final KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
        frameInputMap.put(ctrlEnter, submit);

        frameActionMap.put(submit, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeButtonClick();
            }
        });
    }

    private void setCloseWithKeyboardShortcut(InputMap frameInputMap, ActionMap frameActionMap) {
        final KeyStroke ctrlQ = KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK);

        final String closeActionKey = "CLOSE";
        frameInputMap.put(ctrlQ, closeActionKey);
        frameActionMap.put(closeActionKey, new CloseAction(this));
    }

    private static class CloseAction extends AbstractAction {
        private final JFrame frame;

        public CloseAction(JFrame frame) {
            this.frame = frame;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING));
        }
    }

    private Component createOutputPanel() {
        outputPanel = new JTextArea();
        outputPanel.setEditable(false);
        outputPanel.setVisible(true);
        outputPanel.setAutoscrolls(true);

        final JScrollPane scrollPane = createScrollPane(outputPanel, "Output");
        scrollPane.setVisible(true);

        return scrollPane;
    }

    private JScrollPane createScrollPane(JTextArea templateEditor, String paneTitle) {
        final JScrollPane editorScrollPane = new JScrollPane(templateEditor, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        editorScrollPane.setBorder(BorderFactory.createTitledBorder(paneTitle));
        return editorScrollPane;
    }

    private Component createTextEditor(String templateYaml) {
        final RSyntaxTextArea textEditor = createTextEditorWithSyntaxHighlighting(templateYaml);

        templateEditor = textEditor;

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

        final RTextScrollPane scrollPane = new RTextScrollPane(textEditor, true);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Template"));
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        return scrollPane;
    }

    private RSyntaxTextArea createTextEditorWithSyntaxHighlighting(String templateYaml) {
        // TODO https://github.com/bobbylight/RSyntaxTextArea/issues/269
        JTextComponent.removeKeymap("RTextAreaKeymap");
        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);

        final RSyntaxTextArea textEditor = new RSyntaxTextArea();
        textEditor.setSyntaxEditingStyle(RSyntaxTextArea.SYNTAX_STYLE_YAML);
        textEditor.setEditable(true);
        textEditor.setAntiAliasingEnabled(true);
        textEditor.setTabsEmulated(true);
        textEditor.setAutoIndentEnabled(true);
        textEditor.setTabSize(2);
        textEditor.setText(templateYaml);

        return textEditor;
    }

    private void createControlPanel(Container contentPane, String command) {
        final JPanel topPanel = new JPanel();
        topPanel.setPreferredSize(new Dimension(200, 50));
        topPanel.setLayout(new GridBagLayout());

        commandLineField = new JTextField(command);
        commandLineField.setPreferredSize(new Dimension(200, 25));
        commandLineField.addActionListener(e -> executeButtonClick());
        // TODO add CTRL+L to jump to the field

        final GridBagConstraints textFieldConstraints = new GridBagConstraints();
        textFieldConstraints.gridx = 0;
        textFieldConstraints.gridy = 0;
        textFieldConstraints.weightx = 1.0;
        textFieldConstraints.gridheight = 1;
        textFieldConstraints.insets = new Insets(0, 5, 0, 5);
        textFieldConstraints.fill = GridBagConstraints.HORIZONTAL;

        topPanel.add(commandLineField, textFieldConstraints);

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
            final String templateYaml = templateEditor.getText();
            final Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(templateYaml), null);
        });

        final GridBagConstraints btn2Constraints = new GridBagConstraints();
        btn2Constraints.gridx = 2;
        btn2Constraints.gridy = 0;
        btn2Constraints.gridheight = 1;
        btn2Constraints.insets = new Insets(0, 5, 0, 5);
        topPanel.add(clipboardBtn, btn2Constraints);

        final GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.weightx = 1;
        panelConstraints.gridwidth = 2;
        panelConstraints.fill = GridBagConstraints.BOTH;

        contentPane.add(topPanel, panelConstraints);
    }

    private void executeButtonClick() {
        Utils.writeToFile(this.templateEditor.getText(), temporaryTemplatePath, this::logError);

        this.outputPanel.setText(null);

        Utils.executeCommand(this.commandLineField.getText(),
                             bufferedReader -> bufferedReader.lines()
                                                             .map(line -> line + "\n")
                                                             .forEach(line -> SwingUtilities.invokeLater(() -> {
                                                                 this.outputPanel.append(line);
                                                                 this.outputPanel.repaint();
                                                             })),
                             exitCode -> SwingUtilities.invokeLater(() -> this.outputPanel.append("\nThe process exited with code " + exitCode)),
                             this::logError);
    }

    private void logError(String message) {
        System.err.println(message);

        if (Objects.nonNull(callbacks)) {
            callbacks.printError(message);
        }
    }

    public static void main(String[] args) throws MalformedURLException {
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


        final TemplateGeneratorWindow templateGeneratorWindow = new TemplateGeneratorWindow(url, template);
        templateGeneratorWindow.setDefaultCloseOperation(EXIT_ON_CLOSE);
    }
}
