package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class UserBackupBEBSTest extends WebAuthnTest{

    public UserBackupBEBSTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "User Back-up";
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
        if (request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
//            JSONObject jsonBody = null;
//            HttpParameter attestationObjectParameter = null;
//            String encodedAttestationObject = null;
//            if (Util.isJson(request.bodyToString())) {
//                jsonBody = new JSONObject(request.bodyToString());
//                encodedAttestationObject = (String) Util.getKeyInJsonRecursively(jsonBody, Const.ATTESTATION_OBJECT);
//            } else {
//                attestationObjectParameter  = Util.getNameInParameters(request, Const.ATTESTATION_OBJECT);
//                encodedAttestationObject = attestationObjectParameter.value();
//            }

            String encodedAttestationObject = Util.getAttestationObject(request);

//            if (encodedAttestationObject != null) {

//            Decode attestationObject (sometimes with Base64, sometimes with Base64Url)
//                boolean isUrlEncoding;
//                byte[] cborArray = null;
//                try {
//                    cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
//                    isUrlEncoding = true;
//                } catch (IllegalArgumentException e) {
//                    cborArray = Base64.getDecoder().decode(encodedAttestationObject);
//                    isUrlEncoding = false;
//                }
                byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
                String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
                int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
                byte flags = cborArray[index + rpIdHash.length];

                cborArray[index + rpIdHash.length] = (byte) (flags & 0b11110111); // BE flag
                cborArray[index + rpIdHash.length] = (byte) (flags | 0b00010000); // BS flag

//            String newAttestationObject = isUrlEncoding ? Base64.getUrlEncoder().encodeToString(cborArray) : Base64.getEncoder().encodeToString(cborArray);
            String newAttestationObject = Base64.getUrlEncoder().encodeToString(cborArray).replace("=", "");

//                Special discord case
                if (request.url().toLowerCase().contains("discord".toLowerCase())) {
                    JSONObject jsonBody = new JSONObject(request.bodyToString());
                    JSONObject credentialJSON = new JSONObject(jsonBody.getString("credential"));
                    Util.setValueInJsonRecursively(credentialJSON, Const.ATTESTATION_OBJECT, newAttestationObject);
                    jsonBody = jsonBody.put("credential", credentialJSON.toString());
                    request = request.withBody(jsonBody.toString());
                    return api.http().sendRequest(request).response();
                }

//                if (jsonBody != null) {
//                    Util.setValueInJsonRecursively(jsonBody, Const.ATTESTATION_OBJECT, newAttestationObject.replace("=", ""));
//                    request = request.withBody(jsonBody.toString());
//                } else {
//                    attestationObjectParameter = Util.setNewValueToParameter(attestationObjectParameter, newAttestationObject.replace("=", ""));
//                    request = request.withParameter(attestationObjectParameter);
//                }

            request = Util.setAttestationObject(request, newAttestationObject);

//            }
        } else if (request.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {
//        AUTHENTICATION

//            JSONObject jsonBody = null;
//            HttpParameter authenticatorDataParameter = null;
//            String authenticatorData = null;
//            if (Util.isJson(request.bodyToString())) {
//                jsonBody = new JSONObject(request.bodyToString());
//                authenticatorData = (String) Util.getKeyInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA);
//            } else {
//                authenticatorDataParameter  = Util.getNameInParameters(request, Const.AUTHENTICATOR_DATA);
//                authenticatorData = authenticatorDataParameter.value();
//            }

            String authenticatorData = Util.getAuthenticatorData(request);

//            if (authenticatorData != null) {
//                boolean isUrlEncoding;
//                byte[] cborArray = null;
//                try {
//                    cborArray = Base64.getUrlDecoder().decode(authenticatorData);
//                    isUrlEncoding = true;
//                } catch (IllegalArgumentException e) {
//                    cborArray = Base64.getDecoder().decode(authenticatorData);
//                    isUrlEncoding = false;
//                }
            byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
                int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
                byte flags = cborArray[index + rpIdHash.length];

                cborArray[index + rpIdHash.length] = (byte) (flags & 0b11110111); // BE flag
                cborArray[index + rpIdHash.length] = (byte) (flags | 0b00010000); // BS flag

//            String newAuthenticatorData = isUrlEncoding ? Base64.getUrlEncoder().encodeToString(cborArray) : Base64.getEncoder().encodeToString(cborArray);
            String newAuthenticatorData = Base64.getUrlEncoder().encodeToString(cborArray).replace("=", "");

//                Special discord case
                if (request.url().toLowerCase().contains("discord".toLowerCase())) {
                    JSONObject jsonBody = new JSONObject(request.bodyToString());
                    JSONObject dataJSON = new JSONObject(jsonBody.getString("data"));
                    Util.setValueInJsonRecursively(dataJSON, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
                    jsonBody = jsonBody.put("data", dataJSON.toString());
                    request = request.withBody(jsonBody.toString());
                    return api.http().sendRequest(request).response();
                }

//                UPDATE AUTHENTICATOR DATA AND SIGNATURE
//                if (jsonBody != null) {
//                    Util.setValueInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA, newAuthenticatorData.replace("=", ""));
//                    request = request.withBody(jsonBody.toString());
//                    String signature = Util.recomputeAssertionSignature(request, isUrlEncoding);
//                    Util.setValueInJsonRecursively(jsonBody, Const.SIGNATURE, signature);
//                    request = request.withBody(jsonBody.toString());
//                } else {
//                    authenticatorDataParameter = Util.setNewValueToParameter(authenticatorDataParameter, newAuthenticatorData.replace("=", ""));
//                    request = request.withParameter(authenticatorDataParameter);
//                    String signature = Util.recomputeAssertionSignature(request, isUrlEncoding);
//                    HttpParameter signatureParameter = Util.setNewValueToParameter(Util.getNameInParameters(request, Const.SIGNATURE), signature);
//                    request = request.withParameter(signatureParameter);
//                }
//
                request = Util.setAuthenticatorData(request, newAuthenticatorData);
                request = Util.recomputeAssertionSignature(request);

//            }

        }
        return api.http().sendRequest(request).response();

    }


}
