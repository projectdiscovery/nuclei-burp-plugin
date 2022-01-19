package io.projectdiscovery.nuclei.gui;

import burp.IBurpExtenderCallbacks;
import io.projectdiscovery.nuclei.util.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public class TemplateGeneratorWindow extends JFrame {

    private JTextArea templateEditor;
    private JTextField commandLineField;
    private JTextArea outputPanel;

    private final IBurpExtenderCallbacks callbacks;
    private Path temporaryTemplatePath;

    public TemplateGeneratorWindow(URL targetUrl, String templateYaml) {
        this(targetUrl, templateYaml, null);
    }

    public TemplateGeneratorWindow(URL targetUrl, String templateYaml, IBurpExtenderCallbacks callbacks) {
        super("Nuclei Template Generator"); // TODO setIconImage

        this.callbacks = callbacks;

        this.setLayout(new GridBagLayout());

        setCloseWithKeyboardShortcut();

        String command = createCommand(targetUrl);

        final Container contentPane = this.getContentPane();
        createControlPanel(command, contentPane);
        // TODO use split pane instead?
        createTextEditor(contentPane, templateYaml);
        createOutputPanel(contentPane);

        this.setLocationRelativeTo(null); // center of the screen
        this.setPreferredSize(new Dimension(800, 600));
        this.setMinimumSize(this.getSize());
        this.setVisible(true);
        this.pack();
    }

    private String createCommand(URL targetUrl) {
        try {
            temporaryTemplatePath = Files.createTempFile("nuclei", ".yaml");
        } catch (IOException e) {
            logError("Could not create temporary file: " + e.getMessage());
        }

        // TODO quoting in case of Windows?
        return String.format("nuclei -nc -v -t %s -u %s", temporaryTemplatePath, targetUrl);
    }

    private void setCloseWithKeyboardShortcut() {
        final KeyStroke ctrlQ = KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK);

        final JRootPane rootPane = this.getRootPane();
        final String closeActionKey = "CLOSE";
        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(ctrlQ, closeActionKey);
        rootPane.getActionMap().put(closeActionKey, new CloseAction(this));
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

    private void createOutputPanel(Container contentPane) {
        outputPanel = new JTextArea();
        outputPanel.setEditable(false);
        outputPanel.setVisible(false);
        outputPanel.setAutoscrolls(true);

        final JScrollPane scrollPane = createScrollPane(outputPanel, "Output");
        scrollPane.setVisible(false);

        outputPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                // propagate setVisible from the outputPanel to its parent scroll pane
                scrollPane.setVisible(true);
                scrollPane.getParent().revalidate();

                super.componentShown(e);
            }
        });

        final GridBagConstraints outputConstraints = new GridBagConstraints();
        outputConstraints.gridx = 1;
        outputConstraints.gridy = 1;
        outputConstraints.weightx = 0.5;
        outputConstraints.weighty = 0.9;
        outputConstraints.gridwidth = 1;
        outputConstraints.fill = GridBagConstraints.BOTH;

        contentPane.add(scrollPane, outputConstraints);
    }

    private void createTextEditor(Container contentPane, String templateYaml) {
        templateEditor = new JTextArea();
        templateEditor.setText(templateYaml);
        templateEditor.setEditable(true);

        addKeyboardShortcutsToEditor(templateEditor);

        final JScrollPane editorScrollPane = createScrollPane(templateEditor, "Template");

        final GridBagConstraints textAreaConstraints = new GridBagConstraints();
        textAreaConstraints.fill = GridBagConstraints.BOTH;
        textAreaConstraints.gridwidth = 1;
        textAreaConstraints.gridheight = 1;

        final GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        panelConstraints.weightx = 0.5;
        panelConstraints.weighty = 0.9;
        panelConstraints.gridwidth = 1;
        panelConstraints.fill = GridBagConstraints.BOTH;

        contentPane.add(editorScrollPane, panelConstraints);
    }

    private JScrollPane createScrollPane(JTextArea templateEditor, String template) {
        final JScrollPane editorScrollPane = new JScrollPane(templateEditor, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        editorScrollPane.setBorder(BorderFactory.createTitledBorder(template));
        return editorScrollPane;
    }

    private void addKeyboardShortcutsToEditor(JTextArea templateEditor) {
        final String submit = "text-submit";
        final KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
        templateEditor.getInputMap().put(ctrlEnter, submit);

        final ActionMap editorActionMap = templateEditor.getActionMap();
        editorActionMap.put(submit, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeButtonClick();
            }
        });
    }

    private void createControlPanel(String command, Container contentPane) {
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

        this.outputPanel.setVisible(true);
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

    public void logError(String message) {
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
