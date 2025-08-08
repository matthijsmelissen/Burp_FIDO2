package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

public class SignCountGreaterTest extends WebAuthnTest {
    public SignCountGreaterTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Signature Counter Greater";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

        byte[] rpIdHash = Util.getRpIdHash(request);
        String authenticatorData = Util.getAuthenticatorData(request);

//        Update signature count to 999
        String newAuthenticatorData = Util.changeSignCount(authenticatorData, 999, rpIdHash);

//        Special discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
            Util.setValueInJsonRecursively(dataJSON, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
            jsonBody = jsonBody.put("data", dataJSON.toString());
            request = request.withBody(jsonBody.toString());
            return api.http().sendRequest(request).response();
        }

        request = Util.setAuthenticatorData(request, newAuthenticatorData);
        request = Util.recomputeAssertionSignature(request);

        return api.http().sendRequest(request).response();
    }


}

