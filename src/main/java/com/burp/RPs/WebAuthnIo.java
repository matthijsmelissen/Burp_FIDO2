package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.UUID;

public class WebAuthnIo extends GeneralRP{
    String credentialId;

    public WebAuthnIo(MontoyaApi api) {
        super(api, "webauthn.io");
    }


    /**
     * @param registrationRequests
     * @param tests
     */
    @Override
    public ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {

        for (WebAuthnTest test : tests) {

//            We need a fresh username for each test
            String username = UUID.randomUUID().toString().substring(20);

            for (HttpRequest request : registrationRequests) {
                Thread thread = null;

//            Registration ceremony start
//            Just to retrieve the challenge from webauthn.io
                if (request.url().equals("https://webauthn.io/registration/options")) {

                    thread = new Thread(() -> {

                        JSONObject jsonBody = new JSONObject(request.bodyToString());
//                    Not to use the same username twice
                        Util.setValueInJsonRecursively(jsonBody, Const.USERNAME, username);


                        HttpResponse response = api.http().sendRequest(request.withBody(jsonBody.toString())).response();

//                        JSONObject responseBody = new JSONObject(response.bodyToString());
//                        challenge = (String) Util.getKeyInJsonRecursively(responseBody, Const.CHALLENGE);
                        challenge = Util.getChallengeFromResponse(response); // TODO finish Util.getChallengeFromResponse()
                    });

                } else if (request.url().equals("https://webauthn.io/registration/verification")) { // Registration ceremony verification

                    thread = new Thread(() -> {
                        HttpRequest newRequest = Util.setNewValueToParameter(request, Const.USERNAME, username);

//                        Update challenge value
//                        String clientDataJSON = Util.getClientData(newRequest);
//                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);
//                        newRequest = Util.setClientData(newRequest, newClientDataJSON);
                        newRequest = Util.updateChallengeInRequest(newRequest, challenge);


                        HttpResponse response = test.execute(newRequest);

//                        TODO: add more errors that should not be shown
//                        if ((test instanceof NaiveTest && Util.requestFailed(response)) ||
//                                (!(test instanceof NaiveTest) && !Util.requestFailed(response))) {
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
     */
    @Override
    public ArrayList<AuditIssue> testAuthentication(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests) {
        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {

            for (HttpRequest request : authenticationRequests) {

                Thread thread = null;

//                Authentication ceremony start
//            This part is to retrieve the challenge
                if (request.url().equals("https://webauthn.io/authentication/options")) {

                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

                        challenge = Util.getChallengeFromResponse(response);

//                        Get one of the allowed credentials (= registered credentials)
                        JSONArray allowedCredentials = (JSONArray) Util.getKeyInJsonRecursively(new JSONObject(response.bodyToString()), "allowCredentials");
                        credentialId = (String) Util.getKeyInJsonRecursively(allowedCredentials.getJSONObject(0), Const.ID);
//                    System.out.println(credentialId);
                    });

                } else if (request.url().equals("https://webauthn.io/authentication/verification")) {
//                Actual authentication data

                    thread = new Thread(() -> {

//                        Update ID and rawID
                        HttpRequest newRequest = Util.setNewValueToParameter(request, Const.ID, credentialId);
                        newRequest = Util.setNewValueToParameter(newRequest, Const.RAW_ID, credentialId);


                        String authenticatorData = Util.getAuthenticatorData(newRequest);
                        if (signCount == 0) {
                            signCount = Util.getSignCount(newRequest);
                        }
                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, ++signCount, Util.getRpIdHash(newRequest));
                        newRequest = Util.setAuthenticatorData(newRequest, newAuthenticatorData);

//                        String clientDataJSON = Util.getClientData(newRequest);
//                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);
//                        newRequest = Util.setClientData(newRequest, newClientDataJSON);
                        Util.updateChallengeInRequest(newRequest, challenge);

                        HttpResponse response = test.execute(newRequest);

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
