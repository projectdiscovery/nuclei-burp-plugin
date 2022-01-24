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
import io.projectdiscovery.nuclei.util.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.List;
import java.util.function.Consumer;

public class BurpExtender implements burp.IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Nuclei");

        callbacks.registerContextMenuFactory(createContextMenuFactory(callbacks));

        callbacks.addSuiteTab(createConfigurationTab(callbacks));
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

            final byte invocationContext = invocation.getInvocationContext();
            switch (invocationContext) {
                case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE | IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                    final Consumer<IHttpRequestResponse[]> requestResponseConsumer = (requestResponses) -> generateTemplate(callbacks, requestResponses[0], invocation.getSelectionBounds());

                    menuItems = List.of(messageEditorContextMenu(requestResponseConsumer, invocation));
                    break;
                }
                case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS: {
                    final Consumer<IHttpRequestResponse[]> requestResponseConsumer = (requestResponses) -> generateIntruderTemplate(callbacks, requestResponses[0]);

                    menuItems = List.of(messageEditorContextMenu(requestResponseConsumer, invocation));
                    break;
                }
            }

            return menuItems;
        };
    }

    private JMenuItem messageEditorContextMenu(Consumer<IHttpRequestResponse[]> requestResponseConsumer, IContextMenuInvocation invocation) {
        final JMenuItem menuItem = new JMenuItem("Generate nuclei template");

        menuItem.addActionListener((ActionEvent e) -> {
            final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages.length != 0) {
                requestResponseConsumer.accept(selectedMessages);
            }
        });

        return menuItem;
    }

    private void generateTemplate(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, int[] selectionBounds) {
        final byte[] responseBytes = requestResponse.getResponse();
        final byte[] requestBytes = requestResponse.getRequest();

        final IExtensionHelpers helpers = callbacks.getHelpers();

        final String author = callbacks.loadExtensionSetting(SettingsPanel.AUTHOR_VARIABLE);
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        final TemplateMatcher contentMatcher = Utils.createContentMatcher(responseBytes, responseInfo, selectionBounds);
        final int statusCode = responseInfo.getStatusCode();

        final Requests requests = new Requests();
        requests.setRaw(requestBytes);
        requests.setMatchers(contentMatcher, new Status(statusCode));

        final Template template = new Template("template-id", info, requests);
        final String yamlTemplate = Utils.dumpYaml(template);

        final URL targetUrl = helpers.analyzeRequest(requestResponse.getHttpService(), requestBytes).getUrl();
        SwingUtilities.invokeLater(() -> new TemplateGeneratorWindow(targetUrl, yamlTemplate, callbacks));
    }

    // TODO remove duplicated block
    private void generateIntruderTemplate(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        final byte[] requestBytes = requestResponse.getRequest();

        final IExtensionHelpers helpers = callbacks.getHelpers();

        final String author = callbacks.loadExtensionSetting(SettingsPanel.AUTHOR_VARIABLE);
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Requests requests = new Requests();
        final TransformedRequest intruderRequest = Utils.transformRequestWithPayloads(Requests.AttackType.batteringram, helpers.bytesToString(requestBytes));
        requests.setTransformedRequest(intruderRequest);

        final Template template = new Template("template-id", info, requests);
        final String yamlTemplate = Utils.dumpYaml(template);

        final URL targetUrl = helpers.analyzeRequest(requestResponse.getHttpService(), requestBytes).getUrl();
        SwingUtilities.invokeLater(() -> new TemplateGeneratorWindow(targetUrl, yamlTemplate, callbacks));
    }
}
