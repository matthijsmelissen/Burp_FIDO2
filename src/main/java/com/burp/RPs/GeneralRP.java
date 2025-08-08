package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Tests.WebAuthnTest;
import org.checkerframework.checker.units.qual.A;

import java.util.ArrayList;

public abstract class GeneralRP {
    MontoyaApi api;
    ArrayList<AuditIssue> issues;
    int signCount;
//    byte[] rpIdHash;
    String domain;
    String challenge;

    public GeneralRP(MontoyaApi api, String domain) {
        this.api = api;
        this.domain = domain;
        this.issues = new ArrayList<>();
        this.signCount = 0;
        this.challenge = null;
    }

    public abstract ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests);

    public abstract ArrayList<AuditIssue> testAuthentication(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests);

    public String getDomain() {
        return domain;
    }
}
