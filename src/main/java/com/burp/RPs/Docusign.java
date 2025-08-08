package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class Docusign extends GeneralRP {
    String mestCookie;
    public Docusign(MontoyaApi api) {
        super(api, "account-d.docusign.com");
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

                if (request.url().equals("https://account-d.docusign.com/me/settings/proof/resident-security-key/creation-options")
                        || request.url().equals("https://account-d.docusign.com/me/settings/proof/security-key/creation-options")
                ) {

                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

//                        Get cookie to be set
                        mestCookie = Util.getCookieToBeSet(response, "mest");

//                        Get challenge
                        String responseString = response.bodyToString();
                        JSONObject jsonResponse = new JSONObject(responseString.substring(1, responseString.length() - 1).replace("\\\"", "\""));
                        challenge = jsonResponse.getString(Const.CHALLENGE);

                    });
                }
                else if (request.url().equals("https://account-d.docusign.com/me/settings/proof/security-key")) {
                    thread = new Thread(() -> {

//                        JSONObject jsonRequest = new JSONObject(request.bodyToString());
//                        String newClientData = Util.updateChallengeInClientData(Util.getClientData(request), challenge);
//                        HttpRequest newRequest = Util.setClientData(request, newClientData);
                        HttpRequest newRequest = Util.updateChallengeInRequest(request, challenge);

//                        This can be a function in Util
//                        Change credential id in attestation object
                        String attestationObject = Util.getAttestationObject(newRequest);
                        int credentialIDLength = Util.getCredentialIdFromAttestationObject(attestationObject).length;
                        byte[] randomBytes = new byte[credentialIDLength];
                        new SecureRandom().nextBytes(randomBytes);
                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, randomBytes);
                        newRequest = Util.setAttestationObject(newRequest, newAttestationObject);

//                        Set id and rawId parameters
                        String id = Util.base64UrlEncode(Arrays.toString(randomBytes)).substring(0, 22);
                        newRequest = Util.setIdAndRawId(newRequest, id);

//                        Set cookie
//                        HttpParameter cookieParameter = HttpParameter.parameter("mest", mestCookie, HttpParameterType.COOKIE);
                        newRequest = Util.setCookie(newRequest, "mest", mestCookie);

//                        HttpResponse response = test.execute(newRequest.withUpdatedParameters(cookieParameter));
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
        return null;
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

                if (request.url().equals("https://account-d.docusign.com/securitykeylogin/resident/authoptions") ||
                        request.url().equals("https://account-d.docusign.com/challenges/v1/tsv/security-key/auth-options/") ||
                        request.url().equals("https://account-d.docusign.com/securitykeylogin/authoptions")) {

                    thread = new Thread(() -> {

                        HttpResponse response = api.http().sendRequest(request).response();

//                        Get challenge
//                        TODO challenge = Util.getChallengeFromResponse(response);
                        String responseString = response.bodyToString();
                        JSONObject jsonResponse = new JSONObject(responseString.substring(1, responseString.length() - 1).replace("\\\"", "\""));
                        challenge = jsonResponse.getString(Const.CHALLENGE);
                    });
                } else if (request.url().startsWith("https://account-d.docusign.com/securitykeylogin?") ||
                        request.url().startsWith("https://account-d.docusign.com/password?")) {

                    thread = new Thread(() -> {

//                        String newClientData = Util.updateChallengeInClientData(Util.getClientData(request), challenge);
//                        HttpRequest newRequest = Util.setClientData(request, newClientData);
                        HttpRequest newRequest = Util.updateChallengeInRequest(request, challenge);

//                        String authenticatorData = Util.getAuthenticatorData(request);
//                        String authenticatorData = Util.getAuthenticatorData(newRequest);
                        if (signCount == 0) {
//                            signCount = Util.getSignCount(request) + 1;
                            signCount = Util.getSignCount(newRequest);
                        }
//                        byte[] rpIdHash = Util.getRpIdHash(request);
//                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, signCount, rpIdHash);
//                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, signCount, rpIdHash);
                        newRequest = Util.setSignCount(newRequest, ++signCount);
//                        ++signCount;


//                        String security_key_response = request.parameterValue("security_key_response", HttpParameterType.BODY);
//                        JSONObject jsonResponse = new JSONObject(URLDecoder.decode(URLDecoder.decode(security_key_response, StandardCharsets.UTF_8), StandardCharsets.UTF_8));
//                        Util.setValueInJsonRecursively(jsonResponse, Const.CLIENT_DATA_JSON, newClientData);
//                        Util.setValueInJsonRecursively(jsonResponse, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
//                        String newResponseValue =  URLEncoder.encode(URLEncoder.encode(jsonResponse.toString(), StandardCharsets.UTF_8), StandardCharsets.UTF_8);
//                        HttpParameter newResponseParameter = HttpParameter.bodyParameter("security_key_response", newResponseValue);

//                        HttpResponse response = test.execute(request.withUpdatedParameters(newResponseParameter));
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

        return null;
    }
}
