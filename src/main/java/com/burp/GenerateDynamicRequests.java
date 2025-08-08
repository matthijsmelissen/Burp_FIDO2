package com.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.RPs.GeneralRP;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

public class GenerateDynamicRequests {

    private MontoyaApi api;

    private ArrayList<HttpRequest> registrationRequests;

    private ArrayList<HttpRequest> authenticationRequests;
    private ArrayList<AuditIssue> issues;
    private WebauthnTests webauthnTests;
    private RelyingParties relyingParties;
    public GenerateDynamicRequests(MontoyaApi api) {
        this.api = api;
        this.registrationRequests = new ArrayList<>();
        this.authenticationRequests = new ArrayList<>();
        this.issues = new ArrayList<>();

        this.webauthnTests = new WebauthnTests(api);
        this.relyingParties = new RelyingParties(api);
    }

    public void addRegistrationRequest(HttpRequest request) {
        registrationRequests.add(request);
    }

    public void addAuthenticationRequest(HttpRequest request) {
        authenticationRequests.add(request);
    }

    public ArrayList<HttpRequest> getRegistrationRequests() {
        return registrationRequests;
    }

    public ArrayList<HttpRequest> getAuthenticationRequests() {
        return authenticationRequests;
    }

    public void startRegistrationTest() {

        ArrayList<WebAuthnTest> tests = webauthnTests.getRegistrationTests();
//        After adding the registration requests, the `requestUrl` is the URL of the first request in the list
        String requestUrl = registrationRequests.get(0).url();
        try {
            String host = new URL(requestUrl).getHost();

//            Find the relying party to be tested
            for (GeneralRP relyingParty : relyingParties.getRelyingParties()) {
                if (relyingParty.getDomain().equals(host)) {
//                    Test REGISTRATION and add found issues to be displayed
                    issues.addAll(relyingParty.testRegistration(registrationRequests, tests));
                    break;
                }
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        Util.displayIssues(api, issues);
        issues.clear();
    }

    public void startAuthenticationTest() {

        ArrayList<WebAuthnTest> tests = webauthnTests.getAuthenticationTests();
        String requestUrl = authenticationRequests.get(0).url();

        try {
            String host = new URL(requestUrl).getHost();

//            Find the relying party to be tested
            for (GeneralRP RP : relyingParties.getRelyingParties()) {
                if (RP.getDomain().equals(host)) {
//                    Test AUTHENTICATION and add found issues to be displayed
                    issues.addAll(RP.testAuthentication(authenticationRequests, tests));
                    break;
                }
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        Util.displayIssues(api, issues);
        issues.clear();
    }

/*
    private void keycloakRegistrationTest(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {
        for (WebAuthnTest test : tests) {

            AtomicReference<String> redirectPath = new AtomicReference<>();
            ArrayList<HttpParameter> parametersToBeSent = new ArrayList<>();
            AtomicReference<String> challenge = new AtomicReference<>();

            for (HttpRequest request : registrationRequests) {
                Thread thread = null;
//            api.logging().logToOutput(request.url());


//        FIRST LOGIN PAGE
                if (request.url().contains("/realms/master/protocol/openid-connect/auth")) {
//                    && !request.url().contains("webauthn-register-passwordless")) {

                    thread = new Thread(() -> {

                        HttpParameter kcActionParameter = Util.getKeyInParameters(request, "kc_action");
                        if (kcActionParameter == null || !kcActionParameter.value().equalsIgnoreCase("webauthn-register-passwordless")) {
                            kcActionParameter = HttpParameter.parameter("kc_action", "webauthn-register-passwordless", HttpParameterType.URL);
//                        modifiedRequest.set(request.withParameter(kcActionParameter));
                        }

//                    HttpResponse response = api.http().sendRequest(Util.addParameterInRequest(request, kcActionParameter)).response();
                        HttpResponse response = api.http().sendRequest(request.withParameter(kcActionParameter)).response();


//                    Parse response (include cookies and redirected path in the next request)
                        Element form = Jsoup.parse(response.bodyToString()).getElementById("kc-form-login");

                        if (form != null) {
                            String path = Util.getPathFromURI(form.attr("action"));
//                        api.logging().logToOutput(path);
                            redirectPath.set(path);
//                        api.logging().logToOutput("Path: " + redirectPath);
                        }

                        for (Cookie cookie : response.cookies()) {
                            parametersToBeSent.add(HttpParameter.cookieParameter(cookie.name(), cookie.value()));
                        }
                    });
                } else if (request.url().contains("/realms/master/login-actions/authenticate")) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request.withPath(String.valueOf(redirectPath)).withUpdatedParameters(parametersToBeSent)).response();
//                    api.logging().logToOutput("Location: " + response.headerValue("Location"));
                        String path = Util.getPathFromURI(response.headerValue("Location"));
                        redirectPath.set(path);

//                redirectPath.set("");
//                parametersToBeSent.clear();
                    });
                } else if (request.url().contains("/realms/master/login-actions/required-action") &&
                        !request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request.withPath(String.valueOf(redirectPath)).withUpdatedParameters(parametersToBeSent)).response();

                        Element document = Jsoup.parse(response.bodyToString());
                        Pattern pattern = Pattern.compile("let challenge = \"(.*?)\"");
                        Matcher matcher = pattern.matcher(document.html());
                        if (matcher.find()) {
                            challenge.set(matcher.group(1));
                        }

                        Element form = Jsoup.parse(response.bodyToString()).getElementById("register");
                        if (form != null) {
                            String path = Util.getPathFromURI(form.attr("action"));
                            redirectPath.set(path);
                        }
                    });

                } else if (request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
                    thread = new Thread(() -> {

                        HttpParameter clientDataParameter = Util.getKeyInParameters(request, Const.CLIENT_DATA_JSON);
                        String clientDataJSON = clientDataParameter.value();

                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, String.valueOf(challenge));
                        parametersToBeSent.add(HttpParameter.parameter(clientDataParameter.name(), newClientDataJSON, clientDataParameter.type()));

                        HttpParameter authenticatorLabelParameter = Util.getKeyInParameters(request, "authenticatorLabel");
                        if (authenticatorLabelParameter != null) {
                            parametersToBeSent.add(HttpParameter.parameter(authenticatorLabelParameter.name(),
                                    test.getClass().getName() + "." + Thread.currentThread().getStackTrace()[1].getMethodName(),
                                    authenticatorLabelParameter.type()));
                        }


                        test.execute(request.withUpdatedParameters(parametersToBeSent).withPath(String.valueOf(redirectPath)));

                        parametersToBeSent.clear();

//                        String path = Util.getPathFromURI(response.headerValue("Location"));
//                    api.logging().logToOutput(path);

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

    }

    private void webauthnIoRegistrationTest(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {
        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {
            for (HttpRequest request : registrationRequests) {
                Thread thread = null;

//            Registration ceremony start
//            Just to retrieve the challenge from webauthn.io
                if (!request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {

                    thread = new Thread(() -> {

                        JSONObject jsonBody = new JSONObject(request.bodyToString());
//                    New user
                        Util.setValueInJsonRecursively(jsonBody, Const.USERNAME, "user_" + userCount);

                        HttpResponse response = api.http().sendRequest(request.withBody(jsonBody.toString())).response();

                        JSONObject responseBody = new JSONObject(response.bodyToString());
                        challenge = (String) Util.getKeyInJsonRecursively(responseBody, Const.CHALLENGE);
                    });

                } else { // Registration ceremony verification


                    thread = new Thread(() -> {
                        JSONObject jsonBody = new JSONObject(request.bodyToString());
//                    New user
                        Util.setValueInJsonRecursively(jsonBody, Const.USERNAME, "user_" + userCount);


//                    Update id and RawId
                        byte[] rawId = ("user_" + userCount).getBytes();
//                    Util.setValueInJsonRecursively(body, Const.RAW_ID, new String(rawId));
//                    api.logging().logToOutput(Arrays.toString(rawId));
                        String id = Base64.getUrlEncoder().encodeToString(rawId).replaceAll("=", "");
                        Util.setValueInJsonRecursively(jsonBody, Const.ID, id);
                        Util.setValueInJsonRecursively(jsonBody, Const.RAW_ID, id);

//                        Update challenge value
                        String decodedClientDataJSON = new String(Base64.getDecoder().decode((String) Util.getKeyInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON)));
                        JSONObject clientDataJSON = new JSONObject(decodedClientDataJSON);
                        Util.setValueInJsonRecursively(clientDataJSON, Const.CHALLENGE, challenge);
                        Util.setValueInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON, new String(Base64.getEncoder().encode(clientDataJSON.toString().getBytes())));


                        HttpResponse response = test.execute(request.withBody(jsonBody.toString()));

//                        TODO: add more errors that should not be shown
                        if (!(response.bodyToString().toLowerCase().contains("fail") ||
                                response.bodyToString().toLowerCase().contains("error") ||
                                response.statusCode() == 400)) {

                            issues.add(test.createIssue(request));
                        }

                        userCount++;
                    });

                }

                thread.start();
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                if (!issues.isEmpty()) {
                    api.siteMap().add(issues.remove(0));
                }

            }
        }
    }

    private void keycloakAuthenticationTest(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests) {
        for (WebAuthnTest test : tests) {

            for (HttpRequest request : authenticationRequests) {
                Thread thread = null;

//                api.logging().logToOutput(request.url());

                if (request.url().contains("/realms/master/login-actions/authenticate") &&
                        request.method().equalsIgnoreCase("GET")) {
                    thread = new Thread(() -> {

                    });
                } else if (request.url().contains("/realms/master/login-actions/authenticate") &&
                        request.method().equalsIgnoreCase("POST")) {
                    thread = new Thread(() -> {
//                    HttpParameter signatureParameter = Util.setNewValueToParameter(Util.getKeyInParameters(request, "signature"), newSignature);
//                    HttpResponse response = api.http().sendRequest(testRequest.withParameter(signatureParameter)).response();

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

    }

    private void webauthnIoAuthenticationTest(ArrayList<HttpRequest> authenticationRequests, ArrayList<WebAuthnTest> tests) {
        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {

            for (HttpRequest request : authenticationRequests) {

                Thread thread = null;

//                Authentication ceremony start
                if (!request.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {
//            Authentication request, but does not contain the actual authenticatorData
//            This part is to retrieve the challenge

                    thread = new Thread(() -> {
                        HttpResponse response = api.http().sendRequest(request).response();

                        JSONObject responseBody = new JSONObject(response.bodyToString());
                        challenge = (String) Util.getKeyInJsonRecursively(responseBody, Const.CHALLENGE);

                        JSONArray allowedCredentials = (JSONArray) Util.getKeyInJsonRecursively(responseBody, "allowCredentials");
                        credentialId = (String) Util.getKeyInJsonRecursively(allowedCredentials.getJSONObject(0), Const.ID);
//                    System.out.println(credentialId);
                    });

                } else
                {
//                Actual authentication data

                    thread = new Thread(() -> {

//                    Update Id and RawId
                        JSONObject jsonBody = new JSONObject(request.bodyToString());
                        Util.setValueInJsonRecursively(jsonBody, Const.ID, credentialId);
                        Util.setValueInJsonRecursively(jsonBody, Const.RAW_ID, credentialId);

//                    Util.setValueInJsonRecursively(body, "userHandle", Base64.getEncoder().encodeToString(("user_" + count).getBytes()));

//                    Update signature count
                        String authenticatorData = (String) Util.getKeyInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA);
                        if (rpIdHash == null) {
                            rpIdHash = Util.getRpIdHash(request);
                        }
                        if (signCount == 0) {
                            signCount = Util.getSignCount(request, rpIdHash);
                        }
                        String newAuthenticatorData = Util.changeSignCount(authenticatorData, signCount + 1, rpIdHash);
                        Util.setValueInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
                        ++signCount;

//                        Update challenge value
                        String decodedClientDataJSON = new String(Base64.getDecoder().decode((String) Util.getKeyInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON)));
                        JSONObject clientDataJSON = new JSONObject(decodedClientDataJSON);
                        Util.setValueInJsonRecursively(clientDataJSON, Const.CHALLENGE, challenge);
                        String newClientDataJSON = Base64.getUrlEncoder().encodeToString(clientDataJSON.toString().getBytes()).replace("=", "");
                        Util.setValueInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON, newClientDataJSON);

//                        Recompute signature
                        String newSignature = Util.recomputeAssertionSignature(request.withBody(jsonBody.toString()), true);
                        Util.setValueInJsonRecursively(jsonBody, Const.SIGNATURE, newSignature);

                        HttpResponse response = test.execute(request.withBody(jsonBody.toString()));

//                        TODO: add more errors that should not be shown
                        if (!(response.bodyToString().toLowerCase().contains("fail") ||
                                response.bodyToString().toLowerCase().contains("error") ||
                                response.statusCode() == 400)) {

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

                if (!issues.isEmpty()) {
                    api.siteMap().add(issues.remove(0));
                }

            }
        }
    }
*/


    public void clearRegistrationRequests() {
        registrationRequests.clear();
    }

    public void clearAuthenticationRequests() {
        authenticationRequests.clear();
    }

}
