package io.projectdiscovery.nuclei.gui;

import io.projectdiscovery.nuclei.util.SchemaUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

public final class TemplateGeneratorWindow extends JFrame {

    private final GeneralSettings generalSettings;
    private static TemplateGeneratorWindow instance;
    private final TemplateGeneratorTabbedPane tabbedPane;
    private final java.util.List<TemplateGeneratorTab> templateGeneratorTabs = new ArrayList<>();

    private int openedTabCounter = 1;

    private TemplateGeneratorWindow(GeneralSettings generalSettings) {
        super("Nuclei Template Generator");
        this.setLayout(new BorderLayout());

        this.generalSettings = generalSettings;

        this.tabbedPane = new TemplateGeneratorTabbedPane(this.templateGeneratorTabs);
        this.tabbedPane.addChangeListener(e -> {
            if (((JTabbedPane) e.getSource()).getTabCount() == 0) {
                new CloseAction(TemplateGeneratorWindow.this).actionPerformed(null);
            }
        });
        this.add(this.tabbedPane);

        setKeyboardShortcuts(this.tabbedPane);
        cleanupOnClose();

        this.setJMenuBar(new MenuHelper(this.generalSettings::logError).createMenuBar());
        this.setPreferredSize(new Dimension(800, 600));
        this.setMinimumSize(this.getSize()); // TODO this is platform dependent, custom logic is needed to enforce it
        this.pack();
        this.setLocationRelativeTo(null); // center of the screen
    }

    public static TemplateGeneratorWindow getInstance(GeneralSettings generalSettings) {
        if (instance == null) {
            instance = new TemplateGeneratorWindow(generalSettings);
        }

        return instance;
    }

    public void addTab(TemplateGeneratorTab templateGeneratorTab) {
        this.setVisible(true);
        this.templateGeneratorTabs.add(templateGeneratorTab);
        final String tabName = Optional.ofNullable(templateGeneratorTab.getName())
                                       .orElseGet(() -> "Tab " + this.openedTabCounter++);
        templateGeneratorTab.setName(tabName);
        this.tabbedPane.addTab(tabName, templateGeneratorTab);
    }

    public List<TemplateGeneratorTab> getTabs() {
        return this.templateGeneratorTabs;
    }

    public Optional<TemplateGeneratorTab> getTab(String tabName) {
        return this.templateGeneratorTabs.stream().filter(tab -> tab.getName().equals(tabName)).findAny();
    }

    private void cleanupOnClose() {
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                TemplateGeneratorWindow.this.templateGeneratorTabs.forEach(TemplateGeneratorTab::cleanup);
                TemplateGeneratorWindow.this.templateGeneratorTabs.clear();
                instance = null;
                super.windowClosing(e);
            }
        });
    }

    private void setKeyboardShortcuts(TemplateGeneratorTabbedPane tabbedPane) {
        SwingUtils.setKeyboardShortcut(this.rootPane, KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK), new CloseAction(this));
        SwingUtils.setKeyboardShortcut(this.rootPane, KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK), tabbedPane::removeTab);

        IntStream.rangeClosed(1, 9).forEach(keyIndex -> {
            final char digit = Character.forDigit(keyIndex, 16);
            SwingUtils.setKeyboardShortcut(this.rootPane, KeyStroke.getKeyStroke(digit, InputEvent.CTRL_DOWN_MASK), () -> {

                final int tabIndex = keyIndex - 1;
                if (tabbedPane.getTabCount() > tabIndex) {
                    tabbedPane.setSelectedIndex(tabIndex);
                }
            });
        });

        SwingUtils.setKeyboardShortcut(this.rootPane, KeyEvent.VK_F1, () -> MenuHelper.openDocumentationLink(this.generalSettings::logError));
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

        final GeneralSettings generalSettings = new GeneralSettings.Builder().build();
        final NucleiGeneratorSettings nucleiGeneratorSettings = new NucleiGeneratorSettings.Builder(generalSettings, url, template)
                .withYamlFieldDescriptionMap(SchemaUtils.retrieveYamlFieldWithDescriptions())
                .build();

        final TemplateGeneratorWindow templateGeneratorWindow = new TemplateGeneratorWindow(generalSettings);
        templateGeneratorWindow.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));
        templateGeneratorWindow.addTab(new TemplateGeneratorTab("Custom name", nucleiGeneratorSettings));
        templateGeneratorWindow.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));
        templateGeneratorWindow.addTab(new TemplateGeneratorTab("Another custom name", nucleiGeneratorSettings));
        templateGeneratorWindow.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));

        templateGeneratorWindow.setDefaultCloseOperation(EXIT_ON_CLOSE);
    }
}
