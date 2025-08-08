package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.Cookie;
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

public class Kayak extends GeneralRP {

//    TODO declare this in abstract class
    List<Cookie> cookies;
    public Kayak(MontoyaApi api) {
        super(api, "www.kayak.com");
        cookies = null;
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
                        HttpResponse response = api.http().sendRequest(request).response();

                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
                        challenge = ((String) Util.getKeyInJsonRecursively(jsonResponse, Const.CHALLENGE)).replace("=", "");
//                        challenge = Util.getChallengeFromResponse(response);

                        cookies = response.cookies();
                    });
                } else if (request.url().equals("https://www.kayak.com/auth/webauthn/v1/addCredential")) {
                    thread = new Thread(() -> {
//                        Update challenge in Client Data
                        String clientDataJSON = URLDecoder.decode(Util.getClientData(request), StandardCharsets.UTF_8);
//                        String newClientDataJSON = URLEncoder.encode(Util.updateChallengeInClientData(clientDataJSON, challenge), StandardCharsets.UTF_8);
                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);

//                        (Does not work) New random credentialId parameter
                        HttpParameter credentialId = Util.getNameInParameters(request, "credentialId");
                        HttpParameter newCredentialId = HttpParameter.parameter(credentialId.name(), Util.base64UrlEncode(UUID.randomUUID().toString()).substring(0, 42), credentialId.type());

//                        Change cred id in attestation object
                        String attestationObject = URLDecoder.decode(Util.getAttestationObject(request), StandardCharsets.UTF_8).replace("+", "-").replace("/", "_");
//                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, UUID.randomUUID().toString().getBytes());
                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, test.getTestName().getBytes());
                        newAttestationObject = URLEncoder.encode(newAttestationObject.replace("-", "+").replace("_", "/"), StandardCharsets.UTF_8);

//                        Update Cookies
                        List<HttpParameter> cookieParameters = Util.getParametersFromCookies(cookies);

//                        HttpResponse response = test.execute(Util.setClientData(request, newClientDataJSON).withUpdatedParameters(cookieParameters).withUpdatedParameters(newCredentialId));
                        HttpResponse response = test.execute(Util.setClientData(Util.setAttestationObject(request, newAttestationObject), newClientDataJSON).withUpdatedParameters(cookieParameters).withUpdatedParameters(newCredentialId));

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
        return null;
    }
}
