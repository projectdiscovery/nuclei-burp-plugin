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

package burp;

import io.projectdiscovery.nuclei.gui.*;
import io.projectdiscovery.nuclei.gui.settings.SettingsPanel;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.TemplateUtils;
import io.projectdiscovery.nuclei.yaml.YamlUtil;
import io.projectdiscovery.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class BurpExtender implements burp.IBurpExtender {

    private static final String GENERATE_CONTEXT_MENU_TEXT = "Generate template";

    private static final String GENERATOR_TAB_NAME = "Generator";

    private Map<String, String> yamlFieldDescriptionMap = new HashMap<>();
    private JTabbedPane nucleiTabbedPane;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Nuclei");

        final GeneralSettings generalSettings = new GeneralSettings.Builder()
                .withOutputConsumer(callbacks::printOutput)
                .withErrorConsumer(callbacks::printError)
                .withExtensionSettingSaver(callbacks::saveExtensionSetting)
                .withExtensionSettingLoader(callbacks::loadExtensionSetting)
                .build();

        try {
            callbacks.addSuiteTab(createConfigurationTab(generalSettings));

            initializeNucleiYamlSchema(generalSettings);

            callbacks.registerContextMenuFactory(createContextMenuFactory(generalSettings, callbacks.getHelpers()));
        } catch (Throwable e) {
            JOptionPane.showMessageDialog(null, "There was an error while trying to initialize the plugin. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
            generalSettings.logError("Error while trying to initialize the plugin", e);
        }
    }

    private void initializeNucleiYamlSchema(GeneralSettings generalSettings) {
        this.yamlFieldDescriptionMap = SchemaUtils.retrieveYamlFieldWithDescriptions(generalSettings);
        if (this.yamlFieldDescriptionMap.isEmpty()) {
            generalSettings.logError("AutoCompletion will be disabled, because there was an error while downloading, accessing or parsing the nuclei JSON schema.");
        } else {
            generalSettings.log("JSON schema loaded and parsed!");
        }
    }

    private ITab createConfigurationTab(GeneralSettings generalSettings) {
        return new ITab() {
            @Override
            public String getTabCaption() {
                return "Nuclei";
            }

            @Override
            public Component getUiComponent() {
                final JTabbedPane tabbedPane = new JTabbedPane();
                tabbedPane.addTab("Configuration", new SettingsPanel(generalSettings));
                tabbedPane.setVisible(true);

                BurpExtender.this.nucleiTabbedPane = tabbedPane;
                return tabbedPane;
            }
        };
    }

    private IContextMenuFactory createContextMenuFactory(GeneralSettings generalSettings, IExtensionHelpers extensionHelpers) {
        return (IContextMenuInvocation invocation) -> {
            List<JMenuItem> menuItems = null;

            final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages.length > 0) {

                final IHttpRequestResponse requestResponse = selectedMessages[0];
                final byte[] requestBytes = requestResponse.getRequest();
                final URL targetUrlWithPath = extensionHelpers.analyzeRequest(requestResponse.getHttpService(), requestBytes).getUrl();
                final URL targetUrl;
                try {
                    targetUrl = new URL(targetUrlWithPath.getProtocol(), targetUrlWithPath.getHost(), targetUrlWithPath.getPort(), "/");
                    final int[] selectionBounds = invocation.getSelectionBounds();

                    switch (invocation.getInvocationContext()) {
                        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                            menuItems = createMenuItemsFromHttpRequest(generalSettings, targetUrl, requestBytes, selectionBounds, extensionHelpers);
                            break;
                        }
                        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                            menuItems = createMenuItemsFromHttpResponse(generalSettings, targetUrl, requestResponse, selectionBounds, extensionHelpers);
                            break;
                        }
                        case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS: {
                            final String request = extensionHelpers.bytesToString(requestBytes);
                            menuItems = generateIntruderTemplate(generalSettings, targetUrl, request);
                            break;
                        }
                        case IContextMenuInvocation.CONTEXT_PROXY_HISTORY: {
                            final String[] requests = Arrays.stream(selectedMessages).map(IHttpRequestResponse::getRequest).map(extensionHelpers::bytesToString).toArray(String[]::new);

                            final Http templateRequests = new Http();
                            templateRequests.setRaw(requests);
                            menuItems = new ArrayList<>(List.of(createContextMenuItem(() -> generateTemplate(generalSettings, targetUrl, templateRequests), GENERATE_CONTEXT_MENU_TEXT)));

                            final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, requests);
                            if (!addToTabMenuItems.isEmpty()) {
                                final JMenu addRequestToTabMenu = new JMenu("Add request to");
                                addToTabMenuItems.forEach(addRequestToTabMenu::add);
                                menuItems.add(addRequestToTabMenu);
                            }

                            break;
                        }
                    }
                } catch (MalformedURLException e) {
                    generalSettings.logError(e.getMessage());
                }
            }
            return menuItems;
        };
    }

    private List<JMenuItem> createMenuItemsFromHttpRequest(GeneralSettings generalSettings, URL targetUrl, byte[] requestBytes, int[] selectionBounds, IExtensionHelpers extensionHelpers) {
        final String request = extensionHelpers.bytesToString(requestBytes);

        final JMenuItem generateTemplateContextMenuItem = createTemplateWithHttpRequestContextMenuItem(generalSettings, requestBytes, targetUrl);
        final JMenuItem generateIntruderTemplateMenuItem = createIntruderTemplateMenuItem(generalSettings, targetUrl, request, selectionBounds);

        final List<JMenuItem> menuItems = new ArrayList<>(Arrays.asList(generateTemplateContextMenuItem, generateIntruderTemplateMenuItem));

        final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, new String[]{request});
        if (!addToTabMenuItems.isEmpty()) {
            final JMenu addRequestToTabMenu = new JMenu("Add request to");
            addToTabMenuItems.forEach(addRequestToTabMenu::add);
            menuItems.add(addRequestToTabMenu);
        }

        return menuItems;
    }

    private JMenuItem createIntruderTemplateMenuItem(GeneralSettings generalSettings, URL targetUrl, String request, int[] selectionBounds) {
        final JMenuItem generateIntruderTemplateMenuItem;
        final int startSelectionIndex = selectionBounds[0];
        final int endSelectionIndex = selectionBounds[1];
        if (endSelectionIndex - startSelectionIndex > 0) {
            generateIntruderTemplateMenuItem = createContextMenuItem(() -> {
                final StringBuilder requestModifier = new StringBuilder(request);
                requestModifier.insert(startSelectionIndex, TemplateUtils.INTRUDER_PAYLOAD_MARKER);
                requestModifier.insert(endSelectionIndex + 1, TemplateUtils.INTRUDER_PAYLOAD_MARKER);

                generateIntruderTemplate(generalSettings, targetUrl, requestModifier.toString(), Http.AttackType.batteringram);
            }, "Generate Intruder Template");
        } else {
            generateIntruderTemplateMenuItem = null;
        }
        return generateIntruderTemplateMenuItem;
    }

    private static TemplateGeneratorTabContainer getTemplateGeneratorContainerInstance(GeneralSettings generalSettings) {
        return generalSettings.isDetachedGeneratorWindow() ? TemplateGeneratorWindow.getInstance(generalSettings) : TemplateGeneratorEmbeddedContainer.getInstance(generalSettings);
    }

    private static Set<JMenuItem> createAddRequestToTabContextMenuItems(GeneralSettings generalSettings, String[] requests) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final Consumer<Http> firstRequestConsumer = firstRequest -> firstRequest.addRaw(requests);
            createContextMenuActionHandlingMultiRequests(template, requests, firstRequestConsumer, "request");
        });
    }

    private static Optional<Map.Entry<String, Component>> getTabComponentByName(JTabbedPane tabbedPane, String generatorTabName) {
        return IntStream.range(0, tabbedPane.getTabCount())
                        .mapToObj(i -> Map.entry(tabbedPane.getTitleAt(i), tabbedPane.getComponentAt(i)))
                        .filter(entry -> entry.getKey().equals(generatorTabName))
                        .findFirst();
    }

    private JMenuItem createTemplateWithHttpRequestContextMenuItem(GeneralSettings generalSettings, byte[] requestBytes, URL targetUrl) {
        final Http requests = new Http();
        requests.setRaw(requestBytes);
        return createContextMenuItem(() -> generateTemplate(generalSettings, targetUrl, requests), GENERATE_CONTEXT_MENU_TEXT);
    }

    private List<JMenuItem> createMenuItemsFromHttpResponse(GeneralSettings generalSettings, URL targetUrl, IHttpRequestResponse requestResponse, int[] selectionBounds, IExtensionHelpers extensionHelpers) {
        final byte[] responseBytes = requestResponse.getResponse();
        final IResponseInfo responseInfo = extensionHelpers.analyzeResponse(responseBytes);
        final TemplateMatcher contentMatcher = TemplateUtils.createContentMatcher(responseBytes, responseInfo.getBodyOffset(), selectionBounds, extensionHelpers::bytesToString);

        final JMenuItem generateTemplateContextMenuItem = createContextMenuItem(() -> generateTemplate(generalSettings, contentMatcher, targetUrl, requestResponse, extensionHelpers), GENERATE_CONTEXT_MENU_TEXT);

        final List<JMenuItem> menuItems;
        final String[] request = {extensionHelpers.bytesToString(requestResponse.getRequest())};
        final Set<JMenuItem> addToTabMenuItems = createAddMatcherToTabContextMenuItems(generalSettings, contentMatcher, request);
        if (addToTabMenuItems.isEmpty()) {
            menuItems = List.of(generateTemplateContextMenuItem);
        } else {
            final JMenu addMatcherToTabMenu = new JMenu("Add matcher to");
            addToTabMenuItems.forEach(addMatcherToTabMenu::add);
            menuItems = Arrays.asList(generateTemplateContextMenuItem, addMatcherToTabMenu);
        }

        return menuItems;
    }

    private static Set<JMenuItem> createAddMatcherToTabContextMenuItems(GeneralSettings generalSettings, TemplateMatcher contentMatcher, String[] httpRequest) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final Consumer<Http> firstRequestConsumer = firstRequest -> {
                final List<TemplateMatcher> matchers = firstRequest.getMatchers();
                firstRequest.setMatchers(Utils.createNewList(matchers, contentMatcher));
            };
            createContextMenuActionHandlingMultiRequests(template, httpRequest, firstRequestConsumer, "matcher");
        });
    }

    private static void createContextMenuActionHandlingMultiRequests(Template template, String[] httpRequests, Consumer<Http> firstTemplateRequestConsumer, String errorMessageContext) {
        final List<Http> requests = template.getHttp();

        final int requestSize = requests.size();
        if (requestSize == 0) {
            final Http newRequest = new Http();
            newRequest.setRaw(httpRequests);
            template.setHttp(List.of(newRequest));
        } else {
            if (requestSize > 1) {
                JOptionPane.showMessageDialog(null, String.format("The %s will be added to the first request!", errorMessageContext), "Multiple requests present", JOptionPane.WARNING_MESSAGE);
            }
            firstTemplateRequestConsumer.accept(requests.iterator().next());
        }
    }

    private static Set<JMenuItem> createAddToTabContextMenuItems(GeneralSettings generalSettings, Consumer<Template> templateConsumer) {
        final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);

        return templateGeneratorTabContainer.getTabs().stream().map(tab -> {
            final String tabName = tab.getName();
            // TODO add scrollable menu?
            final Runnable action = () -> templateGeneratorTabContainer.getTab(tabName)
                                                                       .ifPresent(templateGeneratorTab -> templateGeneratorTab.getTemplate().ifPresent(template -> {
                                                                           templateConsumer.accept(template);
                                                                           templateGeneratorTab.setTemplate(template);
                                                                       }));
            return createContextMenuItem(action, tabName);
        }).collect(Collectors.toSet());
    }

    private List<JMenuItem> generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request) {
        final List<JMenuItem> menuItems;
        if (request.chars().filter(c -> c == TemplateUtils.INTRUDER_PAYLOAD_MARKER).count() <= 2) {
            menuItems = List.of(createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, Http.AttackType.batteringram), GENERATE_CONTEXT_MENU_TEXT));
        } else {
            menuItems = Arrays.stream(Http.AttackType.values())
                              .map(attackType -> createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, attackType), GENERATE_CONTEXT_MENU_TEXT + " - " + attackType))
                              .collect(Collectors.toList());
        }
        return menuItems;
    }

    private static JMenuItem createContextMenuItem(Runnable runnable, String menuItemText) {
        final JMenuItem menuItem = new JMenuItem(menuItemText);
        menuItem.addActionListener((ActionEvent e) -> runnable.run());
        return menuItem;
    }

    private void generateTemplate(GeneralSettings generalSettings, TemplateMatcher contentMatcher, URL targetUrl, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        final byte[] responseBytes = requestResponse.getResponse();
        final byte[] requestBytes = requestResponse.getRequest();

        final IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        final int statusCode = responseInfo.getStatusCode();

        final Http requests = new Http();
        requests.setRaw(requestBytes);
        requests.setMatchers(contentMatcher, new Status(statusCode));

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request, Http.AttackType attackType) {
        final Http http = new Http();
        final TransformedRequest intruderRequest = TemplateUtils.transformRequestWithPayloads(attackType, request);
        http.setTransformedRequest(intruderRequest);

        generateTemplate(generalSettings, targetUrl, http);
    }

    private void generateTemplate(GeneralSettings generalSettings, URL targetUrl, Http http) {
        final String author = generalSettings.getAuthor();
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Template template = new Template("template-id", info, http);
        final String normalizedTemplate = TemplateUtils.normalizeTemplate(YamlUtil.dump(template));

        final NucleiGeneratorSettings nucleiGeneratorSettings = new NucleiGeneratorSettings.Builder(generalSettings, targetUrl, normalizedTemplate)
                .withYamlFieldDescriptionMap(this.yamlFieldDescriptionMap)
                .build();

        SwingUtilities.invokeLater(() -> {
            try {
                final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);
                templateGeneratorTabContainer.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));

                if (!generalSettings.isDetachedGeneratorWindow()) {
                    configureEmbeddedGeneratorTab(generalSettings, templateGeneratorTabContainer);
                }
            } catch (Throwable e) {
                JOptionPane.showMessageDialog(null, "There was an error while trying to complete the requested action. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
                generalSettings.logError("Error while trying to generate/show the generated template", e);
            }
        });
    }

    private void configureEmbeddedGeneratorTab(GeneralSettings generalSettings, TemplateGeneratorTabContainer templateGeneratorTabContainer) {
        if (getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).isEmpty()) {
            this.nucleiTabbedPane.addTab(GENERATOR_TAB_NAME, templateGeneratorTabContainer.getComponent());

            final TemplateGeneratorTabbedPane tabbedPane = templateGeneratorTabContainer.getTabbedPane();
            tabbedPane.addChangeListener(e -> {
                if (((JTabbedPane) e.getSource()).getTabCount() == 0) {
                    getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).map(Map.Entry::getValue)
                                                                                    .ifPresentOrElse(generatorTab -> this.nucleiTabbedPane.remove(generatorTab),
                                                                                                     () -> generalSettings.logError("Nuclei Generator tab was not present to remove."));
                    Arrays.stream(tabbedPane.getChangeListeners())
                          .forEach(tabbedPane::removeChangeListener);
                }
            });
        }
    }
}
