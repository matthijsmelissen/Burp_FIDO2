package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class ClientDataCreateTest extends WebAuthnTest{

    public ClientDataCreateTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Client Data create method";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {
//        Get encoded client data
        String encodedClientData = Util.getClientData(request);
//        Decode and to json
        JSONObject clientDataJSON = new JSONObject(new String(Base64.getDecoder().decode(encodedClientData)));
//        Change value in client data
        clientDataJSON.put("type", Const.TEST_EXTENSION);
//        Encode it back
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

//        Set new client data in the request
        request = Util.setClientData(request, newEncodedClientData);

//        Recompute signature if authentication
        if (testType.equals(WebAuthnTestType.AUTHENTICATION)) {
            request = Util.recomputeAssertionSignature(request);
        }

        return api.http().sendRequest(request).response();

    }


}
