package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class UserVerificationTest extends WebAuthnTest {

    public UserVerificationTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "User Verification";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

        byte[] rpIdHash = Util.getRpIdHash(request);

        //        REGISTRATION
        if (testType.equals(WebAuthnTestType.REGISTRATION)) {

            String encodedAttestationObject = Util.getAttestationObject(request);
            byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

                int index = Util.findSubarrayIndex(cborArray, rpIdHash);
                byte flags = cborArray[index + rpIdHash.length];
//            Change UV bit to 0
                cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111011);
            flags = cborArray[index + rpIdHash.length];
//            Change UP to 1 for completeness
            cborArray[index + rpIdHash.length] = (byte) (flags | 0b00000001);

            String newAttestationObject = Util.base64UrlEncode(cborArray);

//                Special discord case
                if (request.url().toLowerCase().contains("discord".toLowerCase())) {
                    JSONObject jsonBody = new JSONObject(request.bodyToString());
                    JSONObject credentialJSON = new JSONObject(jsonBody.getString("credential"));
                    Util.setValueInJsonRecursively(credentialJSON, Const.ATTESTATION_OBJECT, newAttestationObject);
                    jsonBody = jsonBody.put("credential", credentialJSON.toString());
                    request = request.withBody(jsonBody.toString());
                    return api.http().sendRequest(request).response();
                }

            request = Util.setAttestationObject(request, newAttestationObject);

//        AUTHENTICATION
        } else if (testType.equals(WebAuthnTestType.AUTHENTICATION)) {

            String authenticatorData = Util.getAuthenticatorData(request);
            byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

                int index = Util.findSubarrayIndex(cborArray, rpIdHash);
//            Set UserVerification flag to 0
                byte flags = cborArray[index + rpIdHash.length];
                cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111011);
            flags = cborArray[index + rpIdHash.length];
//            Set UP to 1
            cborArray[index + rpIdHash.length] = (byte) (flags | 0b00000001);

            String newAuthenticatorData = Util.base64UrlEncode(cborArray);

//                Special discord case
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

        }

        return api.http().sendRequest(request).response();
    }


}
