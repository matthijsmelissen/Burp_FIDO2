package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class ClientDataChallengeTest extends WebAuthnTest{
    public ClientDataChallengeTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Client Data challenge";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
//    public HttpResponse execute(HttpRequest request, GeneralRP rp) {
    public HttpResponse execute(HttpRequest request) {

        String encodedClientData = Util.getClientData(request);
//        Or URL decode?
        String stringClientData = new String(Base64.getDecoder().decode(encodedClientData));
        JSONObject clientDataJSON = new JSONObject(stringClientData);
        clientDataJSON.put(Const.CHALLENGE, Const.TEST_EXTENSION);
        String newEncodedClientData = Util.base64UrlEncode(clientDataJSON.toString());

        //        Special discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            if (testType.equals(WebAuthnTestType.REGISTRATION)) {
                JSONObject credentialJSON = new JSONObject(jsonBody.getString("credential"));
                Util.setValueInJsonRecursively(credentialJSON, Const.CLIENT_DATA_JSON, newEncodedClientData);
                jsonBody = jsonBody.put("credential", credentialJSON.toString());
            } else if (testType.equals(WebAuthnTestType.AUTHENTICATION)) {
                JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
                Util.setValueInJsonRecursively(dataJSON, Const.CLIENT_DATA_JSON, newEncodedClientData);
                jsonBody = jsonBody.put("data", dataJSON.toString());
            }
            request = request.withBody(jsonBody.toString());
            return api.http().sendRequest(request).response();
        }

        request = Util.setClientData(request, newEncodedClientData);

        if (testType.equals(WebAuthnTestType.AUTHENTICATION)) {
            request = Util.recomputeAssertionSignature(request);
        }

        return api.http().sendRequest(request).response();

    }

}
