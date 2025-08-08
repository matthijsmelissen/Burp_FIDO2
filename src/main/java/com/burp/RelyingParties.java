package com.burp;

import burp.api.montoya.MontoyaApi;
import com.burp.RPs.*;

import java.util.ArrayList;

public class RelyingParties {
//    private MontoyaApi api;
    private final ArrayList<GeneralRP> relyingParties;

    public RelyingParties(MontoyaApi api) {
        this.relyingParties = new ArrayList<>();

        relyingParties.add(new CedarCode(api));
        relyingParties.add(new Discord(api));
        relyingParties.add(new Github(api));
        relyingParties.add(new KeyCloak(api));
        relyingParties.add(new WebAuthnIo(api));
        relyingParties.add(new Docusign(api));
        relyingParties.add(new Kayak(api));
        relyingParties.add(new Shopify(api));
        relyingParties.add(new Bitwarden(api));
    }

    public ArrayList<GeneralRP> getRelyingParties() {
        return relyingParties;
    }
}
