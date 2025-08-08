package com.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final GenerateDynamicRequests generateDynamicRequests;
    public MyContextMenuItemsProvider(MontoyaApi api)
    {
        this.api = api;
        this.generateDynamicRequests = new GenerateDynamicRequests(api);
    }

    /**
     * @param event This object can be queried to find out about HTTP request/responses that are associated with the context menu invocation.
     * @return
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER))
        {
            List<Component> menuItemList = new ArrayList<>();

            JMenuItem registration = new JMenuItem("Add Registration request (added " + generateDynamicRequests.getRegistrationRequests().size() + ")");
            JMenuItem authentication = new JMenuItem("Add Authentication request (added " + generateDynamicRequests.getAuthenticationRequests().size() + ")");
            JMenuItem clearRegistrationRequests = new JMenuItem("Clear registration requests");
            JMenuItem clearAuthenticationRequests = new JMenuItem("Clear authentication requests");
            JMenuItem testRegistration = new JMenuItem("Test Registration");
            JMenuItem testAuthentication = new JMenuItem("Test Authentication");
            JMenuItem clearAll = new JMenuItem("Clear all");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            registration.addActionListener(l -> generateDynamicRequests.addRegistrationRequest(requestResponse.request()));
            menuItemList.add(registration);
            authentication.addActionListener(l -> generateDynamicRequests.addAuthenticationRequest(requestResponse.request()));
            menuItemList.add(authentication);
            clearRegistrationRequests.addActionListener(l -> generateDynamicRequests.clearRegistrationRequests());
            menuItemList.add(clearRegistrationRequests);
            clearAuthenticationRequests.addActionListener(l -> generateDynamicRequests.clearAuthenticationRequests());
            menuItemList.add(clearAuthenticationRequests);
            testRegistration.addActionListener(l -> generateDynamicRequests.startRegistrationTest());
            menuItemList.add(testRegistration);
            testAuthentication.addActionListener(l -> generateDynamicRequests.startAuthenticationTest());
            menuItemList.add(testAuthentication);
            clearAll.addActionListener(l -> {
                generateDynamicRequests.clearAuthenticationRequests();
                generateDynamicRequests.clearRegistrationRequests();
            });
            menuItemList.add(clearAll);

            return menuItemList;
        }

        return null;

    }
}
