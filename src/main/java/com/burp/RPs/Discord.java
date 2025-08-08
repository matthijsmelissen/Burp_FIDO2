package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.JSONArray;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;

public class Discord extends GeneralRP {

//    MontoyaApi api;
    private final String authorization = "";
    String ticket;
    HttpParameter secureRecentMfaCookie;
    HttpHeader mfaAuthorizationHeader;

    public Discord(MontoyaApi api) {
        super(api, "discord.com");
    }


    /**
     * @param registrationRequests
     * @param tests
     * @return
     */
    @Override
    public ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {

        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {
            for (HttpRequest request : registrationRequests) {

//                request = request.withBody("asd");

//                Authorization cookie
                HttpParameter authorizationParameter = HttpParameter.parameter("Authorization", authorization, HttpParameterType.COOKIE);

                Thread thread = null;

//                if (request.url().equals("https://discord.com/api/v9/auth/login")) {
//                    thread = new Thread(() -> {
//                        HttpResponse response = api.http().sendRequest(request).response();
//                    });
//                } else

//                if (request.url().equals("https://discord.com/api/v9/users/@me/mfa/webauthn/credentials")) {
//                    thread = new Thread(() -> {
//                        HttpResponse response = api.http().sendRequest(request.withUpdatedParameters(authorizationParameter)).response();
//
//                        JSONObject jsonResponse = new JSONObject(response);
//                        ticket = (String) Util.getKeyInJsonRecursively(jsonResponse, "ticket");
//                    });
//                } else if (request.url().equals("https://discord.com/api/v9/mfa/finish")) {
//                    thread = new Thread(() -> {
//                        JSONObject jsonRequest = new JSONObject(request);
//                        Util.setValueInJsonRecursively(jsonRequest, "ticket", ticket);
//
//                        HttpResponse response = api.http().sendRequest(request.withBody(jsonRequest.toString()).withUpdatedParameters(authorizationParameter)).response();
//
//                        secureRecentMfaCookie = HttpParameter.parameter("__Secure-recent_mfa", response.cookieValue("__Secure-recent_mfa"), HttpParameterType.COOKIE);
//                        mfaAuthorizationHeader = HttpHeader.httpHeader("X-Discord-Mfa-Authorization", response.cookieValue("__Secure-recent_mfa"));
//
//                    });
//                } else
                if (request.url().equals("https://discord.com/api/v9/users/@me/mfa/webauthn/credentials") &&
                        !request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
                    thread = new Thread(() -> {

//                        To be manually updated every 5 minutes
                        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE3MDA0NzczMDksIm5iZiI6MTcwMDQ3NzMwOSwiZXhwIjoxNzAwNDc3NjA5LCJpc3MiOiJ1cm46ZGlzY29yZC1hcGkiLCJhdWQiOiJ1cm46ZGlzY29yZC1tZmEtcmVwcm9tcHQiLCJ1c2VyIjoxMTc1MDA3OTkzNTAzNDI0NjEzfQ.QpTVX_Qubw9X2BxmbRqFei6EIlbSGpeSAHtqKawMEk4N0qnT4PVSpn0awsx2WMKoTTFmp6PkPhJbPS9JzcMjqw";

                        secureRecentMfaCookie = HttpParameter.parameter("__Secure-recent_mfa", token, HttpParameterType.COOKIE);
                        mfaAuthorizationHeader = HttpHeader.httpHeader("X-Discord-Mfa-Authorization", token);

//                        HttpResponse response = api.http().sendRequest(request.withUpdatedParameters(authorizationParameter, secureRecentMfaCookie).withUpdatedHeader(mfaAuthorizationHeader)).response();
                        HttpResponse response = api.http().sendRequest(request.withUpdatedParameters(secureRecentMfaCookie).withUpdatedHeader(mfaAuthorizationHeader)).response();
//                        HttpResponse response = api.http().sendRequest(request.withUpdatedParameters(secureRecentMfaCookie)).response();

                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
                        String responseWithChallenge = jsonResponse.getString(Const.CHALLENGE).replace("\\\"", "\"");
                        challenge = (String) Util.getKeyInJsonRecursively(new JSONObject(responseWithChallenge), Const.CHALLENGE);

                        ticket = jsonResponse.getString("ticket");
                    });
                } else if (request.url().equals("https://discord.com/api/v9/users/@me/mfa/webauthn/credentials") &&
                        request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
                    thread = new Thread(() -> {

                        JSONObject jsonRequest = new JSONObject(request.bodyToString());
                        jsonRequest = jsonRequest.put("ticket", ticket);

                        String credential = jsonRequest.getString("credential").replace("\\\"", "\"");
                        JSONObject credentialJSON = new JSONObject(credential);
                        String clientDataJSON = (String) Util.getKeyInJsonRecursively(credentialJSON, Const.CLIENT_DATA_JSON);
                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, challenge);
                        Util.setValueInJsonRecursively(credentialJSON, Const.CLIENT_DATA_JSON, newClientDataJSON);

//                        byte[] randomBytes = new byte[16];
//                        new SecureRandom().nextBytes(randomBytes);
//                        String encodedId = Base64.getUrlEncoder().encodeToString(randomBytes).replace("=", "");
//                        Util.setValueInJsonRecursively(credentialJSON, Const.ID, encodedId);
//                        Util.setValueInJsonRecursively(credentialJSON, Const.RAW_ID, encodedId);

                        String attestationObject = (String) Util.getKeyInJsonRecursively(credentialJSON, Const.ATTESTATION_OBJECT);
                        int credentialIDLength = Util.getCredentialIdFromAttestationObject(attestationObject).length;
                        byte[] randomBytes = new byte[credentialIDLength];
                        new SecureRandom().nextBytes(randomBytes);
                        String newAttestationObject = Util.replaceCredIDInAttestationObject(attestationObject, randomBytes);
                        Util.setValueInJsonRecursively(credentialJSON, Const.ATTESTATION_OBJECT, newAttestationObject);


//                        jsonRequest = jsonRequest.put(Const.ID, UUID.randomUUID().toString().substring(20));
                        String randomId = UUID.randomUUID().toString().substring(20);
                        Util.setValueInJsonRecursively(credentialJSON, Const.ID, randomId);
                        Util.setValueInJsonRecursively(credentialJSON, Const.RAW_ID, randomId);

//                        jsonRequest = jsonRequest.put("credential", credentialJSON.toString().replace("\"", "\\\""));
                        jsonRequest = jsonRequest.put("credential", credentialJSON.toString());

//                        HttpResponse response = test.execute(request.withUpdatedParameters(authorizationParameter).withBody(jsonRequest.toString()));
                        HttpResponse response = test.execute(request.withUpdatedParameters(secureRecentMfaCookie).withUpdatedHeader(mfaAuthorizationHeader).withBody(jsonRequest.toString()));

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

        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {
            for (HttpRequest request : authenticationRequests) {

                Thread thread = null;

                if (request.url().equals("https://discord.com/api/v9/users/@me/mfa/webauthn/credentials")) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

                        JSONObject jsonResponse = new JSONObject(response.bodyToString());
//                        JSONObject mfaJson = new JSONObject(jsonResponse.get("mfa"));
                        JSONObject mfaJson = (JSONObject) jsonResponse.get("mfa");
                        ticket = mfaJson.getString("ticket");
                        JSONArray methodsJsonArray = (JSONArray) mfaJson.get("methods");
                        JSONObject methodsJson = (JSONObject) methodsJsonArray.get(0);
                        JSONObject challengeJson = new JSONObject(methodsJson.getString(Const.CHALLENGE));
                        challenge = (String) Util.getKeyInJsonRecursively(challengeJson, Const.CHALLENGE);
                    });
                } else if (request.url().equals("https://discord.com/api/v9/mfa/finish")) {
                    thread = new Thread(() -> {

                        JSONObject jsonRequest = new JSONObject(request.bodyToString());
                        jsonRequest = jsonRequest.put("ticket", ticket);

//                        Update challenge
                        JSONObject dataJson = new JSONObject(jsonRequest.getString("data"));
                        String encodedClientDataJson = (String) Util.getKeyInJsonRecursively(dataJson, Const.CLIENT_DATA_JSON);
                        String newClientDataJSon = Util.updateChallengeInClientData(encodedClientDataJson, challenge);
                        Util.setValueInJsonRecursively(dataJson, Const.CLIENT_DATA_JSON, newClientDataJSon);

//                        Update signature count
                        String authenticatorData = (String) Util.getKeyInJsonRecursively(dataJson, Const.AUTHENTICATOR_DATA);
//                        if (rpIdHash == null) {
//                            rpIdHash = Util.getRpIdHash(request.withBody(dataJson.toString()));
//                        }
                        if (signCount == 0) {
//                            signCount = Util.getSignCount(request.withBody(dataJson.toString()), rpIdHash);
                            signCount = Util.getSignCount(request.withBody(dataJson.toString()));
                        }
//                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, signCount + 1, rpIdHash);
//                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, signCount + 1, Util.getRpIdHash(request.withBody(dataJson.toString())));
//                        Util.setValueInJsonRecursively(dataJson, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
//                        ++signCount;
//                        TODO uncomment following line
//                        newRequest = Util.setSignCount(newRequest, ++signCount);


//                        Recompute signature
                        String newSignature = Util.recomputeAssertionSignature(request.withBody(dataJson.toString()), true);
                        Util.setValueInJsonRecursively(dataJson, Const.SIGNATURE, newSignature);

                        jsonRequest.put("data", dataJson.toString());

                        HttpResponse response = test.execute(request.withBody(jsonRequest.toString()));

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
