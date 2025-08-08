package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Util.Util;

public class NaiveTest extends WebAuthnTest {

    public NaiveTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Naive";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

        if (testType.equals(WebAuthnTestType.AUTHENTICATION)) {
            request = Util.recomputeAssertionSignature(request);
        }

        return api.http().sendRequest(request).response();
    }

}
