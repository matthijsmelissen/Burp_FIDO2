package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class SignatureTest extends WebAuthnTest {
    public SignatureTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Signature";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

//        Special discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
            Util.setValueInJsonRecursively(dataJSON, Const.SIGNATURE, Base64.getUrlEncoder().encodeToString(Const.TEST_EXTENSION.getBytes()));
            jsonBody = jsonBody.put("data", dataJSON.toString());
            return api.http().sendRequest(request.withBody(jsonBody.toString())).response();
        }

//        Set new signature to "Test Extension"
        request = Util.setSignature(request, Util.base64UrlEncode(Const.TEST_EXTENSION));

        return api.http().sendRequest(request).response();

    }



}
