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
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.TemplateUtils;
import io.projectdiscovery.nuclei.yaml.YamlUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public class BurpExtender implements burp.IBurpExtender {

    private static final String DEFAULT_CONTEXT_MENU_TEXT = "Generate template";

    private Map<String, String> yamlFieldDescriptionMap;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Nuclei");

        final GeneralSettings generalSettings = new GeneralSettings.Builder()
                .withOutputConsumer(callbacks::printOutput)
                .withErrorConsumer(callbacks::printError)
                .withExtensionSettingSaver(callbacks::saveExtensionSetting)
                .withExtensionSettingLoader(callbacks::loadExtensionSetting)
                .build();

        initializeNucleiYamlSchema(generalSettings);

        callbacks.registerContextMenuFactory(createContextMenuFactory(generalSettings, callbacks.getHelpers()));

        callbacks.addSuiteTab(createConfigurationTab(generalSettings));
    }

    private void initializeNucleiYamlSchema(GeneralSettings generalSettings) {
        final String errorMessage = "AutoCompletion will be disabled, because there was an error while downloading and parsing the nuclei JSON schema.";

        try {
            this.yamlFieldDescriptionMap = SchemaUtils.retrieveYamlFieldWithDescriptions();
            if (!this.yamlFieldDescriptionMap.isEmpty()) {
                generalSettings.log("JSON schema loaded and parsed!");
            } else {
                generalSettings.logError(errorMessage);
            }
        } catch (Exception e) {
            generalSettings.logError(errorMessage + '\n' + e.getMessage());
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
                final JTabbedPane jTabbedPane = new JTabbedPane();
                jTabbedPane.addTab("Configuration", new SettingsPanel(generalSettings));
                jTabbedPane.setVisible(true);
                return jTabbedPane;
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

                    switch (invocation.getInvocationContext()) {
                        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                            menuItems = generateRequestTemplate(generalSettings, invocation, extensionHelpers, requestBytes, targetUrl);
                            break;
                        }
                        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                            menuItems = List.of(messageEditorContextMenu(() -> generateTemplate(generalSettings, targetUrl, requestResponse, invocation.getSelectionBounds(), extensionHelpers), DEFAULT_CONTEXT_MENU_TEXT));
                            break;
                        }
                        case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS: {
                            final String request = extensionHelpers.bytesToString(requestBytes);
                            menuItems = generateIntruderTemplate(generalSettings, targetUrl, request);
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

    private List<JMenuItem> generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request) {
        final List<JMenuItem> menuItems;
        if (request.chars().filter(c -> c == TemplateUtils.INTRUDER_PAYLOAD_MARKER).count() <= 2) {
            menuItems = List.of(messageEditorContextMenu(() -> generateIntruderTemplate(generalSettings, targetUrl, request, Requests.AttackType.batteringram), DEFAULT_CONTEXT_MENU_TEXT));
        } else {
            menuItems = Arrays.stream(Requests.AttackType.values())
                              .map(attackType -> messageEditorContextMenu(() -> generateIntruderTemplate(generalSettings, targetUrl, request, attackType), DEFAULT_CONTEXT_MENU_TEXT + " - " + attackType))
                              .collect(Collectors.toList());
        }
        return menuItems;
    }

    private JMenuItem messageEditorContextMenu(Runnable runnable, String menuItemText) {
        final JMenuItem menuItem = new JMenuItem(menuItemText);
        menuItem.addActionListener((ActionEvent e) -> runnable.run());
        return menuItem;
    }

    private List<JMenuItem> generateRequestTemplate(GeneralSettings generalSettings, IContextMenuInvocation invocation, IExtensionHelpers helpers, byte[] requestBytes, URL targetUrl) {
        return List.of(messageEditorContextMenu(() -> {
            final int[] selectionBounds = invocation.getSelectionBounds();
            final StringBuilder requestModifier = new StringBuilder(helpers.bytesToString(requestBytes));
            requestModifier.insert(selectionBounds[0], TemplateUtils.INTRUDER_PAYLOAD_MARKER);
            requestModifier.insert(selectionBounds[1] + 1, TemplateUtils.INTRUDER_PAYLOAD_MARKER);

            generateIntruderTemplate(generalSettings, targetUrl, requestModifier.toString(), Requests.AttackType.batteringram);
        }, DEFAULT_CONTEXT_MENU_TEXT));
    }

    private void generateTemplate(GeneralSettings generalSettings, URL targetUrl, IHttpRequestResponse requestResponse, int[] selectionBounds, IExtensionHelpers helpers) {
        final byte[] responseBytes = requestResponse.getResponse();
        final byte[] requestBytes = requestResponse.getRequest();

        final IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        final TemplateMatcher contentMatcher = TemplateUtils.createContentMatcher(responseBytes, responseInfo.getBodyOffset(), selectionBounds, helpers::bytesToString);
        final int statusCode = responseInfo.getStatusCode();

        final Requests requests = new Requests();
        requests.setRaw(requestBytes);
        requests.setMatchers(contentMatcher, new Status(statusCode));

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request, Requests.AttackType attackType) {
        final Requests requests = new Requests();
        final TransformedRequest intruderRequest = TemplateUtils.transformRequestWithPayloads(attackType, request);
        requests.setTransformedRequest(intruderRequest);

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateTemplate(GeneralSettings generalSettings, URL targetUrl, Requests requests) {
        final String author = generalSettings.getAuthor();
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Template template = new Template("template-id", info, requests);
        final String normalizedTemplate = TemplateUtils.normalizeTemplate(YamlUtil.dump(template));

        final NucleiGeneratorSettings nucleiGeneratorSettings = new NucleiGeneratorSettings.Builder(generalSettings, targetUrl, normalizedTemplate)
                .withYamlFieldDescriptionMap(this.yamlFieldDescriptionMap)
                .build();

        SwingUtilities.invokeLater(() -> TemplateGeneratorWindow.getInstance(nucleiGeneratorSettings).addTab(new TemplateGeneratorTab(nucleiGeneratorSettings)));
    }
}
