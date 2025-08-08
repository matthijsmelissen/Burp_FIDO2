package com.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class Burpi implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        this.api.extension().setName("Best WebAuthn scanner!");
        this.logging.logToOutput("Loading successful!");

//        this.api.http().registerHttpHandler(new CustomHttpHandler(api));

//        Delete these
//        CustomHttpRequestResponseEditor customHttpRequestResponseEditor = new CustomHttpRequestResponseEditor(api);
//        api.userInterface().registerHttpRequestEditorProvider(customHttpRequestResponseEditor);

        this.api.userInterface().registerContextMenuItemsProvider(new MyContextMenuItemsProvider(api));
    }

    

}
