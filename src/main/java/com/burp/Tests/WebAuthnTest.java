package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;


public abstract class WebAuthnTest {
    MontoyaApi api;
    String testName;
    String testType;

//    Default constructor?
//    public WebAuthnTest(MontoyaApi api, String testType) {
//        this.api = api;
//        this.testType = testType;
//    }

    public abstract HttpResponse execute(HttpRequest request);

//    public abstract AuditIssue createIssue(HttpRequest request);

    public AuditIssue createIssue(HttpRequest request) {
        return new AuditIssue() {
            @Override
            public String name() {
                return "WebAuthn: " + testName + " test failed.";
            }

            @Override
            public String detail() {
                return switch (testName) {
                    case "RP Id Hash" -> "Make sure the server checks the hash of Relying Party id. " +
                            "It is needed for the server to make sure that the authenticator is registering to the correct Relying Party";
                    case "Authenticator Data" -> "Make sure the server checks the data from the authenticator.";
                    case "Client Data challenge" -> "Make sure the server checks the challenge in client data.";
                    case "Client Data create method" -> "Make sure the server checks the create method in client data.";
                    case "Client Data cross origin" ->
                            "Make sure the server checks the cross origin flag in client data.";
                    case "Client Data origin path with \"/test-path\"", "Client Data origin path \"/\"", "Client Data origin subdomain", "Client Data origin" ->
                            "Make sure the server checks the correct origin of the ceremony.";
                    case "Credential Id" -> "Make sure the server checks the credential id to be authenticated. " +
                            "The server may not accept credential ids that are not previously registered";
                    case "Credential Public Key" ->
                            "Make sure the server checks which public key algorithm the authenticator chose.";
                    case "Signature" -> "Make sure the server checks the signature by the authenticator.";
                    case "Signature Counter" ->
                            "Make sure the server checks that the signature counter sent by the authenticator is greater that the one it has stored.";
                    case "User Back-up" -> "Make sure the server checks the back up bits set by the authenticator.";
                    case "User Presence, no User Verification" ->
                            "Make sure the server checks only the User Presence bit set by the authenticator.";
                    case "User Presence and User Verification" ->
                            "Make sure the server checks both the User Presence and the User Verification bits set by the authenticator.";
                    case "User Verification" ->
                            "Make sure the server checks only the User Verification bit set by the authenticator.";
                    default -> null;
                };
//                return "Normal " + testType + " flow is not working.";
            }

//            TODO personalize alerts!
            @Override
            public String remediation() {
                return switch (testName) {
                    case "RP Id Hash" -> "Make sure the server checks the hash of Relying Party id. " +
                            "It is needed for the server to make sure that the authenticator is registering to the correct Relying Party";
                    case "Authenticator Data" -> "Make sure the server checks the data from the authenticator.";
                    case "Client Data challenge" -> "Make sure the server checks the challenge in client data.";
                    case "Client Data create method" -> "Make sure the server checks the create method in client data.";
                    case "Client Data cross origin" ->
                            "Make sure the server checks the cross origin flag in client data.";
                    case "Client Data origin path with \"/test-path\"", "Client Data origin path \"/\"", "Client Data origin subdomain", "Client Data origin" ->
                            "Make sure the server checks the correct origin of the ceremony.";
                    case "Credential Id" -> "Make sure the server checks the credential id to be authenticated. " +
                            "The server may not accept credential ids that are not previously registered";
                    case "Credential Public Key" ->
                            "Make sure the server checks which public key algorithm the authenticator chose.";
                    case "Signature" -> "Make sure the server checks the signature by the authenticator.";
                    case "Signature Counter" ->
                            "Make sure the server checks that the signature counter sent by the authenticator is greater that the one it has stored.";
                    case "User Back-up" -> "Make sure the server checks the back up bits set by the authenticator.";
                    case "User Presence, no User Verification" ->
                            "Make sure the server checks only the User Presence bit set by the authenticator.";
                    case "User Presence and User Verification" ->
                            "Make sure the server checks both the User Presence and the User Verification bits set by the authenticator.";
                    case "User Verification" ->
                            "Make sure the server checks only the User Verification bit set by the authenticator.";
                    default -> null;
                };
//                return "Make sure the server correctly implements WebAuthn.";
            }

            @Override
            public HttpService httpService() {
                return HttpService.httpService(baseUrl());
            }

            @Override
            public String baseUrl() {
                return request.url();
            }

            @Override
            public AuditIssueSeverity severity() {
                return AuditIssueSeverity.HIGH;
            }

            @Override
            public AuditIssueConfidence confidence() {
                return AuditIssueConfidence.FIRM;
            }

            @Override
            public List<HttpRequestResponse> requestResponses() {
                return null;
            }

            @Override
            public List<Interaction> collaboratorInteractions() {
                return null;
            }

            @Override
            public AuditIssueDefinition definition() {
                return null;
            }
        };
    }

    public String getTestName() {
        return testName;
    }
}
