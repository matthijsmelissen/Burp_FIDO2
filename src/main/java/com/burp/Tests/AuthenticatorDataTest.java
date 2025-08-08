package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class AuthenticatorDataTest extends WebAuthnTest {

    public AuthenticatorDataTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Authenticator Data";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {
//        ONLY AUTHENTICATION

//        Discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
            String newAuthenticatorData = Base64.getUrlEncoder().encodeToString(Const.TEST_EXTENSION.getBytes());
            Util.setValueInJsonRecursively(dataJSON, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
            jsonBody = jsonBody.put("data", dataJSON.toString());

            request = request.withBody(jsonBody.toString());
            return api.http().sendRequest(request).response();
        }

//        Set new authenticator data to "Test Extension"
        request = Util.setAuthenticatorData(request, Util.base64UrlEncode(Const.TEST_EXTENSION));
        request = Util.recomputeAssertionSignature(request);

        return api.http().sendRequest(request).response();

    }

}
