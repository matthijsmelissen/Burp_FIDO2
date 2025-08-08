package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KeyCloak extends GeneralRP {

    public KeyCloak(MontoyaApi api) {
        super(api, "keycloacktest");
    }


    /**
     * @param registrationRequests
     * @param tests
     */
    @Override
    public ArrayList<AuditIssue> testRegistration(ArrayList<HttpRequest> registrationRequests, ArrayList<WebAuthnTest> tests) {
        ArrayList<AuditIssue> issues = new ArrayList<>();

        for (WebAuthnTest test : tests) {

            AtomicReference<String> redirectPath = new AtomicReference<>();
            ArrayList<HttpParameter> parametersToBeSent = new ArrayList<>();
            AtomicReference<String> challenge = new AtomicReference<>();

            for (HttpRequest request : registrationRequests) {
                Thread thread = null;

//        FIRST LOGIN PAGE
                if (request.url().contains("/realms/master/protocol/openid-connect/auth")) {
//                    && !request.url().contains("webauthn-register-passwordless")) {

                    thread = new Thread(() -> {

                        HttpParameter kcActionParameter = Util.getNameInParameters(request, "kc_action");
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

                        HttpParameter clientDataParameter = Util.getNameInParameters(request, Const.CLIENT_DATA_JSON);
                        String clientDataJSON = clientDataParameter.value();

                        String newClientDataJSON = Util.updateChallengeInClientData(clientDataJSON, String.valueOf(challenge));
                        parametersToBeSent.add(HttpParameter.parameter(clientDataParameter.name(), newClientDataJSON, clientDataParameter.type()));

                        HttpParameter authenticatorLabelParameter = Util.getNameInParameters(request, "authenticatorLabel");
                        if (authenticatorLabelParameter != null) {
                            parametersToBeSent.add(HttpParameter.parameter(authenticatorLabelParameter.name(),
                                    test.getClass().getName() + "." + Thread.currentThread().getStackTrace()[1].getMethodName(),
                                    authenticatorLabelParameter.type()));
                        }


                        HttpResponse response = test.execute(request.withUpdatedParameters(parametersToBeSent).withPath(String.valueOf(redirectPath)));

//                        TODO: add more errors that should not be shown
                        if (!Util.requestFailed(response)) {
                            issues.add(test.createIssue(request));
                        }

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

//                if (!issues.isEmpty()) {
//                    api.siteMap().add(issues.remove(0));
//                }
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

                        HttpResponse response = test.execute(request);

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
