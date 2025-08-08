package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class Shopify extends GeneralRP {
    public Shopify(MontoyaApi api) {
        super(api, "accounts.shopify.com");
    }

    /**
     * @param registrationRequests
     * @param tests
     * @return
     */
    @Override
    public ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {
        for (WebAuthnTest test : tests) {
            for (HttpRequest request : registrationRequests) {

                Thread thread = null;

                if (request.url().equals("https://www.kayak.com/auth/webauthn/v1/newCredentialParams")) {
                    thread = new Thread(() -> {

                    });
                } else if (request.url().equals("https://www.kayak.com/auth/webauthn/v1/addCredential")) {
                    thread = new Thread(() -> {
//                        if (!Util.requestFailed(response)) {
//                            issues.add(test.createIssue(request));
//                        }
                    });
                }


                thread.start();
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }


            }
        }

        return issues;
    }

    /**
     * @param authenticationRequests
     * @param tests
     * @return
     */
    @Override
    public ArrayList<AuditIssue> testAuthentication(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests) {
        return null;
    }
}
