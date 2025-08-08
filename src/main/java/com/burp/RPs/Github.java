package com.burp.RPs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.burp.Tests.WebAuthnTest;
import com.burp.Util.Util;
import org.json.HTTP;
import org.json.JSONObject;
import org.jsoup.Jsoup;

import java.util.ArrayList;
import java.util.Base64;

public class Github extends GeneralRP {

    String cookieGhSessString;
    String authenticityTokenString;
    String timestamp;
    String timestampSecret;
    String challenge;

    public Github(MontoyaApi api) {
        super(api, "github.com");
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

                Thread thread = new Thread(() -> {

                    HttpResponse response = test.execute(request);

                    if (!Util.requestFailed(response)) {
                        issues.add(test.createIssue(request));
                    }
                });

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

                if (request.url().equalsIgnoreCase("https://github.com/u2f/login_fragment?is_emu_login=false")) {
                     thread = new Thread(() -> {

                        HttpResponse response = api.http().sendRequest(request).response();

                        authenticityTokenString = Jsoup.parse(response.bodyToString()).select("input[name=authenticity_token]").attr("value");
                        cookieGhSessString = response.cookieValue("_gh_sess");
                        timestamp = Jsoup.parse(response.bodyToString()).select("input[name=timestamp]").last().attr("value");
                        timestampSecret = Jsoup.parse(response.bodyToString()).select("input[name=timestamp_secret]").last().attr("value");

                        String req = Jsoup.parse(response.bodyToString()).select("form.js-conditional-webauthn-placeholder").first().attr("data-webauthn-sign-request");
                        JSONObject reqJson = new JSONObject(req);
                        challenge = (String) Util.getKeyInJsonRecursively(reqJson, Const.CHALLENGE);

                    });
                } else if (request.url().equalsIgnoreCase("https://github.com/session")) {

                    thread = new Thread(() -> {

                        HttpRequest newRequest = Util.setNewValueToParameter(request, "authenticity_token", authenticityTokenString);
                        newRequest = Util.setCookie(newRequest, "_gh_sess", cookieGhSessString);
                        newRequest = Util.setNewValueToParameter(newRequest, "timestamp", timestamp);
                        newRequest = Util.setNewValueToParameter(newRequest, "timestamp_secret", timestampSecret);

                        newRequest = Util.updateChallengeInRequest(newRequest, challenge);


                        if (signCount == 0) {
                            signCount = Util.getSignCount(request);
                        }
                        newRequest = Util.setSignCount(newRequest, ++signCount);

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
