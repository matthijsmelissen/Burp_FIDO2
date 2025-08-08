package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.ArrayList;

public class Bitwarden extends GeneralRP {
    private String session;
    public Bitwarden(MontoyaApi api) {
        super(api, "v4.passwordless.dev");
        this.session = null;
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

                if (request.url().equals("https://v4.passwordless.dev/register/begin")) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
                        challenge = ((String) Util.getKeyInJsonRecursively(jsonResponse, Const.CHALLENGE));
                        session = ((String) Util.getKeyInJsonRecursively(jsonResponse, "session"));
                    });
                } else if (request.url().equals("https://v4.passwordless.dev/register/complete")) {
                    thread = new Thread(() -> {

                        JSONObject jsonBody = new JSONObject(request.bodyToString());

//                        Update challenge in Client Data
                        String clientDataJSON = Util.getClientData(request);
                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);

//                        (Does not work) New random credentialId parameter
//                        HttpParameter credentialId = Util.getNameInParameters(request, "credentialId");
//                        HttpParameter newCredentialId = HttpParameter.parameter(credentialId.name(), Util.base64UrlEncode(UUID.randomUUID().toString()).substring(0, 42), credentialId.type());

//                        Change cred id in attestation object
                        String attestationObject = Util.getAttestationObject(request);
                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, test.getTestName().getBytes());

                        Util.setValueInJsonRecursively(jsonBody, "session", session);
                        Util.setValueInJsonRecursively(jsonBody, "clientDataJson", newClientDataJSON);
                        Util.setValueInJsonRecursively(jsonBody, "AttestationObject", newAttestationObject);

                        HttpResponse response = test.execute(request.withBody(jsonBody.toString()));

                        if (!Util.requestFailed(response)) {
                            issues.add(test.createIssue(request));
                        }
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
        for (WebAuthnTest test : tests) {

            for (HttpRequest request : authenticationRequests) {

                Thread thread = null;

                if (request.url().equals("https://v4.passwordless.dev/register/begin")) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
                        challenge = ((String) Util.getKeyInJsonRecursively(jsonResponse, Const.CHALLENGE));
                        session = ((String) Util.getKeyInJsonRecursively(jsonResponse, "session"));
                    });
                } else if (request.url().equals("https://v4.passwordless.dev/register/complete")) {
                    thread = new Thread(() -> {

                        JSONObject jsonBody = new JSONObject(request.bodyToString());

//                        Update challenge in Client Data
                        String clientDataJSON = Util.getClientData(request);
                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);

//                        (Does not work) New random credentialId parameter
//                        HttpParameter credentialId = Util.getNameInParameters(request, "credentialId");
//                        HttpParameter newCredentialId = HttpParameter.parameter(credentialId.name(), Util.base64UrlEncode(UUID.randomUUID().toString()).substring(0, 42), credentialId.type());

//                        Change cred id in attestation object
                        String attestationObject = Util.getAttestationObject(request);
                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, test.getTestName().getBytes());

                        Util.setValueInJsonRecursively(jsonBody, "session", session);
                        Util.setValueInJsonRecursively(jsonBody, "clientDataJson", newClientDataJSON);
                        Util.setValueInJsonRecursively(jsonBody, "AttestationObject", newAttestationObject);

                        HttpResponse response = test.execute(request.withBody(jsonBody.toString()));

                        if (!Util.requestFailed(response)) {
                            issues.add(test.createIssue(request));
                        }
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
}
