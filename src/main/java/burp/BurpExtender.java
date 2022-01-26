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

import io.projectdiscovery.nuclei.gui.SettingsPanel;
import io.projectdiscovery.nuclei.gui.TemplateGeneratorWindow;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class BurpExtender implements burp.IBurpExtender {

    private Map<String, String> yamlFieldDescriptionMap;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Nuclei");

        // TODO apply callbacks.customizeUiComponent to created UI components

        initializeNucleiYamlSchema(callbacks);

        callbacks.registerContextMenuFactory(createContextMenuFactory(callbacks));

        callbacks.addSuiteTab(createConfigurationTab(callbacks));
    }

    private void initializeNucleiYamlSchema(IBurpExtenderCallbacks callbacks) {
        final String errorMessage = "AutoCompletion will be disabled, because there was an error while downloading and parsing the nuclei JSON schema.";

        try {
            this.yamlFieldDescriptionMap = SchemaUtils.retrieveYamlFieldWithDescriptions();
            if (!this.yamlFieldDescriptionMap.isEmpty()) {
                callbacks.printOutput("JSON schema loaded and parsed!");
            } else {
                callbacks.printError(errorMessage);
            }
        } catch (Exception e) {
            callbacks.printError(errorMessage + '\n' + e.getMessage());
        }
    }

    private ITab createConfigurationTab(IBurpExtenderCallbacks callbacks) {
        return new ITab() {
            @Override
            public String getTabCaption() {
                return "Nuclei";
            }

            @Override
            public Component getUiComponent() {
                final JTabbedPane jTabbedPane = new JTabbedPane();
                jTabbedPane.addTab("Configuration", new SettingsPanel(callbacks));
                jTabbedPane.setVisible(true);
                return jTabbedPane;
            }
        };
    }

    private IContextMenuFactory createContextMenuFactory(IBurpExtenderCallbacks callbacks) {
        return (IContextMenuInvocation invocation) -> {
            List<JMenuItem> menuItems = null;

            final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages.length > 0) {
                final IExtensionHelpers helpers = callbacks.getHelpers();

                final IHttpRequestResponse requestResponse = selectedMessages[0];
                final byte[] requestBytes = requestResponse.getRequest();
                final URL targetUrl = helpers.analyzeRequest(requestResponse.getHttpService(), requestBytes).getUrl();

                switch (invocation.getInvocationContext()) {
                    case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                    case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                        menuItems = List.of(messageEditorContextMenu(() -> generateIntruderTemplate(targetUrl, helpers.bytesToString(requestBytes), invocation.getSelectionBounds(), callbacks)));
                        break;
                    }
                    case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                    case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                        menuItems = List.of(messageEditorContextMenu(() -> generateTemplate(targetUrl, requestResponse, invocation.getSelectionBounds(), callbacks)));
                        break;
                    }
                    case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS: {
                        menuItems = List.of(messageEditorContextMenu(() -> generateIntruderTemplate(targetUrl, helpers.bytesToString(requestBytes), callbacks)));
                        break;
                    }
                }
            }
            return menuItems;
        };
    }

    private JMenuItem messageEditorContextMenu(Runnable runnable) {
        final JMenuItem menuItem = new JMenuItem("Generate nuclei template");
        menuItem.addActionListener((ActionEvent e) -> runnable.run());
        return menuItem;
    }

    private void generateTemplate(URL targetUrl, IHttpRequestResponse requestResponse, int[] selectionBounds, IBurpExtenderCallbacks callbacks) {
        final byte[] responseBytes = requestResponse.getResponse();
        final byte[] requestBytes = requestResponse.getRequest();

        final IExtensionHelpers helpers = callbacks.getHelpers();

        final IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        final TemplateMatcher contentMatcher = Utils.createContentMatcher(responseBytes, responseInfo, selectionBounds);
        final int statusCode = responseInfo.getStatusCode();

        final Requests requests = new Requests();
        requests.setRaw(requestBytes);
        requests.setMatchers(contentMatcher, new Status(statusCode));

        generateTemplate(targetUrl, requests, callbacks);
    }

    private void generateIntruderTemplate(URL targetUrl, String request, int[] selectionBounds, IBurpExtenderCallbacks callbacks) {
        final StringBuilder stringBuilder = new StringBuilder(request);
        stringBuilder.insert(selectionBounds[0], Utils.INTRUDER_PAYLOAD_MARKER);
        stringBuilder.insert(selectionBounds[1] + 1, Utils.INTRUDER_PAYLOAD_MARKER);

        generateIntruderTemplate(targetUrl, stringBuilder.toString(), callbacks);
    }

    private void generateIntruderTemplate(URL targetUrl, String request, IBurpExtenderCallbacks callbacks) {
        final Requests requests = new Requests();
        final TransformedRequest intruderRequest = Utils.transformRequestWithPayloads(Requests.AttackType.batteringram, request);
        requests.setTransformedRequest(intruderRequest);

        generateTemplate(targetUrl, requests, callbacks);
    }

    private void generateTemplate(URL targetUrl, Requests requests, IBurpExtenderCallbacks callbacks) {
        final String author = callbacks.loadExtensionSetting(SettingsPanel.AUTHOR_VARIABLE);
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Template template = new Template("template-id", info, requests);
        final String yamlTemplate = Utils.dumpYaml(template);

        SwingUtilities.invokeLater(() -> new TemplateGeneratorWindow(Utils.getNucleiPath(callbacks), targetUrl, yamlTemplate, this.yamlFieldDescriptionMap, callbacks));
    }
}
