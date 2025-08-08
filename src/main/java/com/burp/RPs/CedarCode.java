package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.UUID;


public class CedarCode extends GeneralRP {
    String sessionCookie;

    public CedarCode(MontoyaApi api) {
        super(api, "webauthn.cedarcode.com");
        this.sessionCookie = null;
    }


    /**
     * @param registrationRequests
     * @param tests
     */
    @Override
    public ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {

        for (WebAuthnTest test : tests) {
            for (HttpRequest request : registrationRequests) {

                Thread thread = null;

                if (request.url().equals("https://webauthn.cedarcode.com/registration")) {

                    thread = new Thread(() -> {
                        HttpRequest newRequest = Util.setNewValueToParameter(request, "registration%5Busername%5D", UUID.randomUUID().toString());
                        newRequest = Util.setNewValueToParameter(newRequest, "registration%5Bnickname%5D", URLEncoder.encode(Const.TEST_EXTENSION, StandardCharsets.UTF_8));

                        HttpResponse response = api.http().sendRequest(newRequest).response();

//                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
//                        challenge = (String) Util.getKeyInJsonRecursively(jsonResponse, Const.CHALLENGE);
                        challenge = Util.getChallengeFromResponse(response);
                        sessionCookie = response.cookies().get(0).value();
                    });

                } else if (request.url().startsWith("https://webauthn.cedarcode.com/registration/callback?credential_nickname=")) {
                    thread = new Thread(() -> {
//                        Update ClientDataJSON
//                        String clientDataJSON = Util.getClientData(request);
//                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);
//                        HttpRequest newRequest = Util.setClientData(request, newClientDataJSON);
                        HttpRequest newRequest = Util.updateChallengeInRequest(request, challenge);

//                        Update id and rawId with random ones
                        String randomEncodedId = Util.base64UrlEncode(UUID.randomUUID().toString());
                        newRequest = Util.setIdAndRawId(newRequest, randomEncodedId);

//                        Update cookie parameter
                        newRequest = Util.setCookie(newRequest, "_webauthn_app_session", sessionCookie);


//                        Update URL parameter: credential_nickname -> Const.TEST_EXTENSION
                        newRequest = Util.setNewValueToParameter(newRequest, "credential_nickname", URLEncoder.encode(Const.TEST_EXTENSION, StandardCharsets.UTF_8));

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

    /**
     * @param authenticationRequests
     * @param tests
     */
    @Override
    public ArrayList<AuditIssue> testAuthentication(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests) {

        for (WebAuthnTest test : tests) {
            for (HttpRequest request : authenticationRequests) {

                Thread thread = null;

                if (request.url().equals("https://webauthn.cedarcode.com/session")) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

//                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
//                        challenge = (String) Util.getKeyInJsonRecursively(jsonResponse, Const.CHALLENGE);
                        challenge = Util.getChallengeFromResponse(response);

                        sessionCookie = response.cookies().get(0).value();
                    });
                } else if (request.url().equals("https://webauthn.cedarcode.com/session/callback")) {
                    thread = new Thread(() -> {
//                        Update challenge in Client Data
//                        String clientDataJSON = Util.getClientData(request);
//                        String newClientData = Util.updateChallengeInClientData(clientDataJSON, challenge);
//                        HttpRequest newRequest = Util.setClientData(request, newClientData);
                        HttpRequest newRequest = Util.updateChallengeInRequest(request, challenge);

//                        Update signature count
                        String authenticatorData = Util.getAuthenticatorData(newRequest);

                        if (signCount == 0) { // first authentication test
                            signCount = Util.getSignCount(newRequest);
                        }
                        newRequest = Util.setSignCount(newRequest, ++signCount);

//                        Update Cookie parameter
                        HttpParameter newCookieParameter = HttpParameter.cookieParameter("_webauthn_app_session", sessionCookie);

//                        HttpResponse response = test.execute(request.withBody(jsonRequest.toString()).withUpdatedParameters(newCookieParameter));
                        HttpResponse response = test.execute(newRequest.withUpdatedParameters(newCookieParameter));


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
