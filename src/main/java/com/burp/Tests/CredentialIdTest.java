package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class CredentialIdTest extends WebAuthnTest {

//    TODO: this changes the id and rawId in the request, but NOT in the attestationObject or authenticatorData

    public CredentialIdTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Credential Id";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

//        Discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
            Util.setValueInJsonRecursively(dataJSON, Const.ID, Base64.getUrlEncoder().encodeToString(Const.TEST_EXTENSION.getBytes()));
            Util.setValueInJsonRecursively(dataJSON, Const.RAW_ID, Base64.getUrlEncoder().encodeToString(Const.TEST_EXTENSION.getBytes()));
            jsonBody = jsonBody.put("data", dataJSON.toString());

            request = request.withBody(jsonBody.toString());
            return api.http().sendRequest(request).response();
        }

//        Change id and rawId to "Test Extension"
        request = Util.setIdAndRawId(request, Util.base64UrlEncode(Const.TEST_EXTENSION));
        request = Util.recomputeAssertionSignature(request);

        return api.http().sendRequest(request).response();

    }



}
