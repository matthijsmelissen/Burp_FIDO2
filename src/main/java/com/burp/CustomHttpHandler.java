package com.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.burp.Util.Util;
import com.webauthn4j.data.attestation.AttestationObject;
import org.json.JSONObject;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

// Util


public class CustomHttpHandler implements HttpHandler {
    private final MontoyaApi api;

    //    Variables need to be saved for later user
    private byte[] rpIdHash;
    private AttestationObject attestationObject;

//    https://www.iana.org/assignments/cose/cose.xhtml
    private final int[] deprecatedAlgs;

    public CustomHttpHandler(MontoyaApi api) {
        this.api = api;

        this.rpIdHash = null;
        this.attestationObject = null;
        this.deprecatedAlgs = new int[]{-65535, -65534, -65533, -65532, -65531, -65530, -65529, -260, -259, -258, -257, -47};
    }


    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

//        Filter for only POST or PATCH requests
        if (!requestToBeSent.method().equalsIgnoreCase("POST") && !requestToBeSent.method().equalsIgnoreCase("PATCH") ) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        if (!requestToBeSent.body().toString().toLowerCase().contains("attestationObject".toLowerCase()) &&
                !requestToBeSent.body().toString().toLowerCase().contains("authenticatorData".toLowerCase()) &&
                !requestToBeSent.body().toString().toLowerCase().contains("username".toLowerCase())) { // webauthn.io first registration request
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }


        if (requestToBeSent.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {

//            return RequestToBeSentAction.continueWith(changeUVTo1(requestToBeSent));

//                Util.getKeyInJsonRecursively(body, "attestationObject") != null) {

//            Util.sendSessionRequestsWithDifferentUsername(api, sessions.get(requestToBeSent.headerValue("Host")));
//            api.http().sendRequest(requestToBeSent.withAddedHeader("Ignore", "Ignore"));
//            Util.sendSessionRequestsWithDifferentUsername(api, sessions.get(requestToBeSent.headerValue("Host")));
//            api.http().sendRequest(requestToBeSent.withAddedHeader("Ignore", "Ignore"));


//            Extract rpIdHash -> need to be saved in the class variable
//            TODO not ideal
//            rpIdHash = Util.getRpIdHash(requestToBeSent);

//            REGISTRATION
//            https://www.w3.org/TR/webauthn-3/#sctn-rp-operations

//            changePublicKeyAlgorithm(body, -260); // -260 is insecure

//            7-9
//            verifyWebauthnCreate(body, requestToBeSent);
//            verifyWebauthnChallenge(body, requestToBeSent);
//            verifyWebauthnOrigin(body, requestToBeSent);
//            TODO: 13 top origin

//            13-16
//            verifyAttestationRpIdHash(body, requestToBeSent);
//            changeUPJson(body, rpIdHash, requestToBeSent);
//            changeUVJ
//            son(body, rpIdHash, requestToBeSent);
//            changeBEBSJson(body, rpIdHash, requestToBeSent);

//            19
//            verifyCredentialPublicKey(body, requestToBeSent);

        } else if (requestToBeSent.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {
//            if (Util.getKeyInJsonRecursively(body, "authenticatorData") != null) {
//            AUTHENTICATION
//            https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion

//            naiveTest(body, requestToBeSent);

//            5
//            verifyCredentialId(body, requestToBeSent);

//            10-12
//            verifyWebauthnCreate(body, requestToBeSent);
//            verifyWebauthnChallenge(body, requestToBeSent);
//            verifyWebauthnOrigin(body, requestToBeSent);
//            TODO: 13 top origin

//            14
//            verifyAuthenticatorData(body, requestToBeSent);

//            15-17
//            changeUPJson(body, rpIdHash, requestToBeSent);
//            changeUVJson(body, rpIdHash, requestToBeSent);
//            HttpRequestToBeSent newRequest = changeUVTo1(requestToBeSent);
//            changeBEBSJson(body, rpIdHash, requestToBeSent);

//            21
//            verifySignature(body, requestToBeSent);

//            22
//            verifySignCount(body, requestToBeSent);

//            Not considered: attestationObject, extensions, top origin
        }


        /*if (isJson) {
            return RequestToBeSentAction.continueWith(requestToBeSent.withBody(body.toString()));
//            return RequestToBeSentAction.continueWith(requestToBeSent);
        } else
        {
//            Effectively final variable
            ParsedHttpParameter finalParameter = parameter;
            JSONObject finalBody = body;
            ParsedHttpParameter newParameter = new ParsedHttpParameter() {
                @Override
                public HttpParameterType type() {
                    return finalParameter.type();
                }

                @Override
                public String name() {
                    return finalParameter.name();
                }

                @Override
                public String value() {
                    return URLEncoder.encode(finalBody.toString(), StandardCharsets.UTF_8);
                }

                @Override
                public Range nameOffsets() {
                    return null;
                }

                @Override
                public Range valueOffsets() {
                    return null;
                }
            };
            return RequestToBeSentAction.continueWith(requestToBeSent.withParameter(newParameter));
        }*/
//        HttpRequest modifiedHttpRequest = requestToBeSent.withBody(body.toString());
//        return RequestToBeSentAction.continueWith(modifiedHttpRequest);

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    private HttpRequest changeUVTo1(HttpRequestToBeSent request) {

        if (request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {
            JSONObject jsonObject = new JSONObject(request.bodyToString());

            String attestationObject = (String) Util.getKeyInJsonRecursively(jsonObject, Const.ATTESTATION_OBJECT);
            byte[] cborArray = Base64.getUrlDecoder().decode(attestationObject);
            byte[] rpIdHash = Util.getRpIdHash(request);
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags | 0b00000100);

            Util.setValueInJsonRecursively(jsonObject, Const.ATTESTATION_OBJECT, Base64.getUrlEncoder().encodeToString(cborArray));
            jsonObject = jsonObject.put("ciao", "ciao");

            return request.withBody(jsonObject.toString());

        } else if (request.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {

            HttpParameter parameter = Util.getNameInParameters(request, "security_key_response");
            JSONObject jsonObject = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));

            String authenticatorData = (String) jsonObject.get(Const.AUTHENTICATOR_DATA);
            byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);
            byte[] rpItHash = Util.getRpIdHash(request);
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

    //            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111011);

            jsonObject.put(Const.AUTHENTICATOR_DATA, Base64.getUrlEncoder().encodeToString(cborArray));

            HttpRequest newRequest = request.withParameter(HttpParameter.bodyParameter("security_key_response", URLEncoder.encode(URLEncoder.encode(jsonObject.toString(), StandardCharsets.UTF_8), StandardCharsets.UTF_8)));
            return (HttpRequestToBeSent) newRequest;
        }

        return request;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {

//        testAlgs(responseReceived, api);

        return ResponseReceivedAction.continueWith(responseReceived);
    }


    private void naiveTest(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        recomputeAssertionSignature(body, true);
//        requestToBeSent = requestToBeSent.withBody(body.toString());
    }

    private void recomputeAssertionSignature(JSONObject body, boolean isUrlEncoding) {

        String clientData = (String) Util.getKeyInJsonRecursively(body, Const.CLIENT_DATA_JSON);
        String authenticatorData = (String) Util.getKeyInJsonRecursively(body, Const.AUTHENTICATOR_DATA);
//        String origSignature = (String) Util.getKeyInJsonRecursively(body, Const.SIGNATURE);

        byte[] clientDataBytes = isUrlEncoding ? Base64.getUrlDecoder().decode(clientData) : Base64.getDecoder().decode(clientData);
        byte[] decodedAuthenticatorData = isUrlEncoding ? Base64.getUrlDecoder().decode(authenticatorData) : Base64.getDecoder().decode(authenticatorData);
//        byte[] decodedSignature = isUrlEncoding ? Base64.getUrlDecoder().decode(origSignature) : Base64.getDecoder().decode(origSignature); // just for testing

        try {
//        SHA256 of the clientDataJSON
            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);

//        https://w3c.github.io/webauthn/#sctn-op-get-assertion
//        Concatenate two values and create assertion signature
            ByteArrayOutputStream concatenatedByteArray = new ByteArrayOutputStream();
            concatenatedByteArray.write(decodedAuthenticatorData);
            concatenatedByteArray.write(clientDataHash);
            byte[] data = concatenatedByteArray.toByteArray();

//        Get private key
            PrivateKey privateKey = Util.getPrivateKey("/Users/pchen/Downloads/Private key.pem");

//        Sign new data (format: https://w3c.github.io/webauthn/#sctn-signature-attestation-types)
            byte[] signature = Util.sign(data, privateKey);

            String encodedSignature = isUrlEncoding ? Base64.getUrlEncoder().encodeToString(signature) : Base64.getEncoder().encodeToString(signature);
//            Discord case
            if (body.toString().contains("ticket")) {
                JSONObject dataJson = new JSONObject(body.getString("data"));
                Util.setValueInJsonRecursively(dataJson, Const.SIGNATURE, encodedSignature.replace("=", ""));
                Util.setValueInJsonRecursively(body, "data", dataJson.toString());
            } else {
                Util.setValueInJsonRecursively(body, Const.SIGNATURE, encodedSignature.replace("=", ""));
            }
//            return isUrlEncoding ? Base64.getUrlEncoder().encodeToString(signature).replace("=", "") : Base64.getEncoder().encodeToString(signature).replace("=", "");
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

      /*
    private void verifySignCount(JSONObject body, HttpRequestToBeSent requestToBeSent) {
//        New method added in Util!
String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");

        boolean isUrlEncoding;
        byte[] cborArray = null;
        try {
            cborArray = Base64.getUrlDecoder().decode(authenticatorData);
            isUrlEncoding = true;
        } catch (IllegalArgumentException e) {
            cborArray = Base64.getDecoder().decode(authenticatorData);
            isUrlEncoding = false;
        }
        String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
        int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Change signCount bytes to all 0s (lowest possible)
//        https://www.w3.org/TR/webauthn-3/#fig-attStructs
        for (int i = 0; i < 3; i++) {
            cborArray[index + rpIdHash.length + 1 + i] = (byte) 0;
        }
//        https://github.com/MicrosoftEdge/webauthnsample/blob/master/fido.js
//        If signCount == 0; the request may be discarded
        cborArray[index + rpIdHash.length + 4] = (byte) 1;



        String newAuthenticatorData = null;
        if (isUrlEncoding) {
            newAuthenticatorData = new String(Base64.getUrlEncoder().encode(cborArray));
            byte[] newCbor = Base64.getUrlDecoder().decode(newAuthenticatorData); // just for debugging
        } else {
            newAuthenticatorData = new String(Base64.getEncoder().encode(cborArray));
            byte[] newCbor = Base64.getDecoder().decode(newAuthenticatorData); // just for debugging
        }

        Util.setValueInJsonRecursively(body, "authenticatorData", newAuthenticatorData.replace("=", ""));
        Util.recomputeAssertionSignature(body, isUrlEncoding);


        Util.changeSignCount(body, 1, rpIdHash); // Minimum value

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
        return;
    }

    private void verifySignature(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        Util.setValueInJsonRecursively(body, "signature", Base64.getUrlEncoder().encodeToString("Test Extension".getBytes()));

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void verifyCredentialId(JSONObject body, HttpRequestToBeSent requestToBeSent) {
//        String id = (String) Util.getKeyInJsonRecursively(body, "id");
//        String rawId = (String) Util.getKeyInJsonRecursively(body, "rawId");

        Util.setValueInJsonRecursively(body, "id", Base64.getUrlEncoder().encodeToString("Test Extension".getBytes()));
        Util.setValueInJsonRecursively(body, "rawId", Base64.getUrlEncoder().encodeToString("Test Extension".getBytes()));

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));

    }

    private void verifyCredentialPublicKey(JSONObject body, HttpRequestToBeSent requestToBeSent) {
//        https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples

        String encodedAttestationObject = (String) Util.getKeyInJsonRecursively(body, "attestationObject");

        if (encodedAttestationObject != null) {
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//        WE ASSUME FOR NOW THAT ES256 IS ALWAYS USED
//        WE TRY TO CHANGE TO ALG HERE
            int algIndex = Util.findSubarrayIndex(cborArray, new byte[]{26});

//        Change alg to another one
            cborArray[algIndex] = (byte) (37);
            String newAttestationObject = null;
            if (isUrlEncoding) {
                newAttestationObject = new String(Base64.getUrlEncoder().encode(cborArray));
            } else {
                newAttestationObject = new String(Base64.getEncoder().encode(cborArray));
            }
            Util.setValueInJsonRecursively(body, "attestationObject", newAttestationObject);

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));

            return;

//        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
//        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
//        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
//        attestationObject = attestationObjectConverter.convert(cborArray);
//        COSEKey key = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
//        System.out.println(key.getAlgorithm());
//        System.out.println(attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid());
//        System.out.println(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId());
        }


        String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");

        if (authenticatorData != null) {
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(authenticatorData);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(authenticatorData);
                isUrlEncoding = false;
            }            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex


//        WE ASSUME FOR NOW THAT ES256 IS ALWAYS USED
//        WE TRY TO CHANGE TO ALG HERE
            int algIndex = Util.findSubarrayIndex(cborArray, new byte[]{26});

//        Change alg to another one
            cborArray[algIndex] = (byte) (37);

            String newAuthenticatorData = null;
            if (isUrlEncoding) {
                newAuthenticatorData = new String(Base64.getUrlEncoder().encode(cborArray));
                byte[] newCbor = Base64.getUrlDecoder().decode(newAuthenticatorData); // just for debugging
            } else {
                newAuthenticatorData = new String(Base64.getEncoder().encode(cborArray));
                byte[] newCbor = Base64.getDecoder().decode(newAuthenticatorData); // just for debugging
            }

            Util.setValueInJsonRecursively(body, "authenticatorData", newAuthenticatorData.replace("=", ""));
            Util.recomputeAssertionSignature(body, isUrlEncoding);

//            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
            return;
        }
    }

    private void changeBEBSJson(JSONObject body, byte[] rpIdHash, HttpRequestToBeSent requestToBeSent) {
        //        REGISTRATION
        String encodedAttestationObject = (String) Util.getKeyInJsonRecursively(body, "attestationObject");

        if (encodedAttestationObject != null) {
//            Decode attestationObject (sometimes with Base64, sometimes with Base64Url)
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11110111); // BE flag
            cborArray[index + rpIdHash.length] = (byte) (flags | 0b00010000); // BS flag

            String newAttestationObject = null;
            if (isUrlEncoding) {
                newAttestationObject = new String(Base64.getUrlEncoder().encode(cborArray));
            } else {
                newAttestationObject = new String(Base64.getEncoder().encode(cborArray));
            }
            Util.setValueInJsonRecursively(body, "attestationObject", newAttestationObject.replace("=", ""));

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
        }

        //        AUTHENTICATION
        String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");

        if (authenticatorData != null) {
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(authenticatorData);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(authenticatorData);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11110111); // BE flag
            cborArray[index + rpIdHash.length] = (byte) (flags | 0b00010000); // BS flag

            String newAuthenticatorData = null;
            if (isUrlEncoding) {
                newAuthenticatorData = new String(Base64.getUrlEncoder().encode(cborArray));
                byte[] newCbor = Base64.getUrlDecoder().decode(newAuthenticatorData); // just for debugging
            } else {
                newAuthenticatorData = new String(Base64.getEncoder().encode(cborArray));
                byte[] newCbor = Base64.getDecoder().decode(newAuthenticatorData); // just for debugging
            }

            Util.setValueInJsonRecursively(body, "authenticatorData", newAuthenticatorData.replace("=", ""));
            Util.recomputeAssertionSignature(body, isUrlEncoding);

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
            return;
        }

    }

    private void verifyAttestationRpIdHash(JSONObject body, HttpRequestToBeSent requestToBeSent) {

        String encodedAttestationObject = (String) Util.getKeyInJsonRecursively(body, "attestationObject");
        boolean isUrlEncoding;
        byte[] cborArray = null;
        try {
            cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
            isUrlEncoding = true;
        } catch (IllegalArgumentException e) {
            cborArray = Base64.getDecoder().decode(encodedAttestationObject);
            isUrlEncoding = false;
        }
        String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

        int rpIdHashIndex = Util.findSubarrayIndex(cborArray, rpIdHash);

        System.arraycopy("Test Extension".getBytes(), 0, cborArray, rpIdHashIndex, "Test Extension".getBytes().length);

        if (isUrlEncoding) {
            Util.setValueInJsonRecursively(body, "attestationObject", Base64.getUrlEncoder().encodeToString(cborArray));
        } else {
            Util.setValueInJsonRecursively(body, "attestationObject", Base64.getEncoder().encodeToString(cborArray));
        }

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void verifyWebauthnCreate(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        String clientDataJSON = (String) Util.getKeyInJsonRecursively(body, "clientDataJSON");

        String encodedClientData = new String(Base64.getDecoder().decode(clientDataJSON));

        JSONObject clientData = new JSONObject(encodedClientData);

        clientData.put("type", "Test Extension");

        Util.setValueInJsonRecursively(body, "clientDataJSON", Base64.getEncoder().encodeToString(clientData.toString().getBytes()));

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void verifyWebauthnChallenge(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        String clientDataJSON = (String) Util.getKeyInJsonRecursively(body, "clientDataJSON");

        String encodedClientData = new String(Base64.getDecoder().decode(clientDataJSON));

        JSONObject clientData = new JSONObject(encodedClientData);

        clientData.put("challenge", "Test Extension");

        Util.setValueInJsonRecursively(body, "clientDataJSON", Base64.getEncoder().encodeToString(clientData.toString().getBytes()));

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void verifyWebauthnOrigin(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        String clientDataJSON = (String) Util.getKeyInJsonRecursively(body, "clientDataJSON");

        String encodedClientData = new String(Base64.getDecoder().decode(clientDataJSON));

        JSONObject clientData = new JSONObject(encodedClientData);

        clientData.put("origin", "Test Extension");

        Util.setValueInJsonRecursively(body, "clientDataJSON", Base64.getEncoder().encodeToString(clientData.toString().getBytes()));

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void verifyAuthenticatorData(JSONObject body, HttpRequestToBeSent requestToBeSent) {
        Util.setValueInJsonRecursively(body, "authenticatorData", "Test Extension");

        this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
    }

    private void changeUPJson(JSONObject body, byte[] rpIdHash, HttpRequestToBeSent requestToBeSent) {
//        TODO: eliminate duplicate part of code

//        REGISTRATION
        String encodedAttestationObject = (String) Util.getKeyInJsonRecursively(body, "attestationObject");

        if (encodedAttestationObject != null) {
//            Decode attestationObject (sometimes with Base64, sometimes with Base64Url)
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
//            Change UP bit to 0
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111110);

            String newAttestationObject = null;
            if (isUrlEncoding) {
                newAttestationObject = new String(Base64.getUrlEncoder().encode(cborArray));
            } else {
                newAttestationObject = new String(Base64.getEncoder().encode(cborArray));
            }
            Util.setValueInJsonRecursively(body, "attestationObject", newAttestationObject.replace("=", ""));

//            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));

            return;
        }

//        AUTHENTICATION
        String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");

        if (authenticatorData != null) {
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(authenticatorData);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(authenticatorData);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111110);

            String newAuthenticatorData = null;
            if (isUrlEncoding) {
                newAuthenticatorData = new String(Base64.getUrlEncoder().encode(cborArray));
                byte[] newCbor = Base64.getUrlDecoder().decode(newAuthenticatorData); // just for debugging
            } else {
                newAuthenticatorData = new String(Base64.getEncoder().encode(cborArray));
                byte[] newCbor = Base64.getDecoder().decode(newAuthenticatorData); // just for debugging
            }

            Util.setValueInJsonRecursively(body, "authenticatorData", newAuthenticatorData.replace("=", ""));
            Util.recomputeAssertionSignature(body, isUrlEncoding);

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
            return;
        }

    }

    private void changeUVJson(JSONObject body, byte[] rpIdHash, HttpRequestToBeSent requestToBeSent) {
//        TODO: eliminate duplicate part of code

//        REGISTRATION
        String encodedAttestationObject = (String) Util.getKeyInJsonRecursively(body, "attestationObject");

        if (encodedAttestationObject != null) {
//            Decode attestationObject (sometimes with Base64, sometimes with Base64Url)
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
                isUrlEncoding = false;
            }
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
//            Change UP bit to 0
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111011);

            String newAttestationObject = null;
            if (isUrlEncoding) {
                newAttestationObject = new String(Base64.getUrlEncoder().encode(cborArray));
            } else {
                newAttestationObject = new String(Base64.getEncoder().encode(cborArray));
            }
            Util.setValueInJsonRecursively(body, "attestationObject", newAttestationObject.replace("=", ""));

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));

            return;
        }

//        AUTHENTICATION
        String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");

        if (authenticatorData != null) {
            boolean isUrlEncoding;
            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(authenticatorData);
                isUrlEncoding = true;
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(authenticatorData);
                isUrlEncoding = false;
            }            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            Get flags byte
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111011);

            String newAuthenticatorData = null;
            if (isUrlEncoding) {
                newAuthenticatorData = new String(Base64.getUrlEncoder().encode(cborArray));
                byte[] newCbor = Base64.getUrlDecoder().decode(newAuthenticatorData); // just for debugging
            } else {
                newAuthenticatorData = new String(Base64.getEncoder().encode(cborArray));
                byte[] newCbor = Base64.getDecoder().decode(newAuthenticatorData); // just for debugging
            }

            Util.setValueInJsonRecursively(body, "authenticatorData", newAuthenticatorData.replace("=", ""));
            Util.recomputeAssertionSignature(body, isUrlEncoding);

            this.api.http().sendRequest(requestToBeSent.withBody(body.toString()));
            return;
        }
    }



    private void testAlgs(HttpResponseReceived responseReceived, MontoyaApi api) {
        if (!responseReceived.body().toString().contains("pubKeyCredParams")) {
            return;
        }

//        String x = "{\"rp\": {\"name\": \"webauthn.io\", \"id\": \"webauthn.io\"}, \"user\": {\"id\": \"cXFx\", \"name\": \"qqq\", \"displayName\": \"qqq\"}, \"challenge\": \"JmY0kWYCOv8DfZvqaRhqXCbXfo9YkGrLK6ntwCbbefo1EVMaak9tMo3EoPn-bPWo-qB8A7OolnbDFH9Vke4Z6g\", \"pubKeyCredParams\": [{\"type\": \"public-key\", \"alg\": -7}, {\"type\": \"public-key\", \"alg\": -257}], \"timeout\": 60000, \"excludeCredentials\": [{\"id\": \"CWetOQi79D5hqTTeSIcxsg\", \"type\": \"public-key\", \"transports\": [\"nfc\", \"usb\"]}, {\"id\": \"g8AqPrwK0KjULOZ4hOISQ5r4-DYQuIJTlrMckTYUFr8\", \"type\": \"public-key\", \"transports\": [\"internal\"]}, {\"id\": \"FBrGPO4XLhQ5hHRdnjXcAjaWNOe_huhflAZZ4Le8Efc4NfpPTH58kavKZnf-USra\", \"type\": \"public-key\", \"transports\": [\"usb\"]}], \"authenticatorSelection\": {\"residentKey\": \"preferred\", \"requireResidentKey\": false, \"userVerification\": \"preferred\"}, \"attestation\": \"none\", \"extensions\": {\"credProps\": true}}";

//        String body = " <body>\n" +
//                "    <div class=\"cfba097d8 cd717c1e0\">\n" +
//                "  \n" +
//                "<main class=\"c9f0ef1f7 cbc24b689\">\n" +
//                "  <section class=\"ce128f585 _prompt-box-outer\">\n" +
//                "    <div class=\"cd130f380 c804ab97b\">\n" +
//                "      <input type=\"hidden\" id=\"config\" value=\"{&#34;publicKey&#34;:{&#34;challenge&#34;:&#34;8UOYxoICrM1C9Jqg5ORbx0Zpfp_bvc9uCi5wsEywdjw&#34;,&#34;rp&#34;:{&#34;name&#34;:&#34;dev-u1qzr35q3vqeqd23&#34;,&#34;id&#34;:&#34;dev-u1qzr35q3vqeqd23.us.auth0.com&#34;},&#34;user&#34;:{&#34;id&#34;:&#34;BGqNN3DYE1fo9UovyeROsElw587pQsDVfyI1Ai3o7Eo7NWlUAgSCxJoFXqlshVnR&#34;,&#34;name&#34;:&#34;123@asd.com&#34;,&#34;displayName&#34;:&#34;123&#34;},&#34;pubKeyCredParams&#34;:[{&#34;alg&#34;:-7,&#34;type&#34;:&#34;public-key&#34;},{&#34;alg&#34;:-257,&#34;type&#34;:&#34;public-key&#34;}],&#34;authenticatorSelection&#34;:{&#34;userVerification&#34;:&#34;required&#34;,&#34;authenticatorAttachment&#34;:&#34;platform&#34;},&#34;timeout&#34;:60000,&#34;attestation&#34;:&#34;none&#34;,&#34;excludeCredentials&#34;:[]}}\" />";

        String body = responseReceived.body().toString();

        JSONObject response = null;

//        Make JSON
        try {
            response = new JSONObject(body);
        } catch (JSONException e) {
//            System.out.println(e.getMessage());

//            Auth0
            Document html = Jsoup.parse(body);
            Element publicKeysJson = html.getElementById("config");
            if (publicKeysJson != null && publicKeysJson.val().contains("pubKeyCredParams")) {
                response = new JSONObject(publicKeysJson.val());
            }

        }

        if (response != null) {
            JSONArray allowedAlgorithms = (JSONArray) Util.getKeyInJsonRecursively(response, "pubKeyCredParams");
            JSONObject rp = (JSONObject) Util.getKeyInJsonRecursively(response, "rp");
            String host = rp.getString("id");

            for (int i = 0; i < allowedAlgorithms.length(); i++) {
                JSONObject alg = allowedAlgorithms.getJSONObject(i);
                int algIndex = (Integer) alg.get("alg");

                if (Arrays.stream(deprecatedAlgs).anyMatch(deprecatedAlg -> deprecatedAlg == algIndex)) {
                    Util.createAlgsIssue(algIndex, host, api);
                }
            }
        }

    }

    private HttpRequest testWebauthnIo(HttpRequest request) {

        if (!request.method().equals("POST")) {
            return request;
        }

        byte[] rpIdHash = null;

        if (request.url().equals("https://webauthn.io/registration/verification") || request.url().equals("https://localhost/registration/verification")) {
            JSONObject body = new JSONObject(request.body().toString());

//            rpIdHash = Util.getRpIdHash(body);

//            Util.changeUPJson(body);

//            Util.changePublicKeyAlgorithm(body, -260);

            return request.withBody(body.toString());
        }

        if (request.url().equals("https://webauthn.io/authentication/verification") || request.url().equals("https://localhost/authentication/verification")) {

//            https://github.com/webauthn4j/webauthn4j/blob/91cfb144055a3f130c6874a579be2a705bfa80e6/webauthn4j-test/src/main/java/com/webauthn4j/test/TestDataUtil.java#L385
//            ObjectMapper jsonMapper = new ObjectMapper();
//            ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
//            cborMapper.registerModule(new DeviceCheckCBORModule());
//            ObjectConverter objectConverter = new ObjectConverter(jsonMapper, cborMapper);
//            AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);


//            Get request's original body
            JSONObject body = new JSONObject(request.body().toString());

            try {

//                Util.changeUPJson(body);


//                Extract relevant values
                String clientData = (String) Util.getKeyInJsonRecursively(body, "clientDataJSON");
                byte[] clientDataBytes = Base64.getDecoder().decode(clientData);
                String authenticatorData = (String) Util.getKeyInJsonRecursively(body, "authenticatorData");
                byte[] decodedAuthenticatorData = Base64.getUrlDecoder().decode(authenticatorData);
                String origSignature = (String) Util.getKeyInJsonRecursively(body, "signature");
                byte[] decodedSignature = Base64.getUrlDecoder().decode(origSignature); // just for testing

//                SHA256 of the clientDataJSON
                byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);


//                https://w3c.github.io/webauthn/#sctn-op-get-assertion
//                Concatenate two values and create assertion signature
                ByteArrayOutputStream concatenatedByteArray = new ByteArrayOutputStream();
                concatenatedByteArray.write(decodedAuthenticatorData);
                concatenatedByteArray.write(clientDataHash);
                byte[] data = concatenatedByteArray.toByteArray();

//                Get private key
                PrivateKey privateKey = Util.getPrivateKey("/Users/pchen/Downloads/Private key.pem");

//                Sign new data (format: https://w3c.github.io/webauthn/#sctn-signature-attestation-types)
                byte[] signature = Util.sign(body, data, privateKey);

                Util.setValueInJsonRecursively(body, "signature", new String(signature));
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }

//            Return updated request
//            return request.withBody(body.toString());
            return request;
        }


//                Replace the extra key
//                stringJsonAttObject = stringJsonAttObject.replace("        \"1\" : 2\n", "");

//                String -> Json
                JSONObject jsonResponse = new JSONObject(stringJsonAttObject);

                String test = jsonResponse.toString();
                byte[] testtest = test.getBytes();
                AttestationObject testtesttest = attestationObjectConverter.convert(testtest);


                jsonResponse.getJSONObject("authData").put("flagUP", false);
//                JSONObject newAuthData = jsonResponse.getJSONObject("authData").put("flagUP", false);
//                JSONObject newJsonResponse = jsonResponse.put("authData", newAuthData);

//                Json -> String
//                String newStringJsonAttObject = newJsonResponse.toString(2);
                String newStringJsonAttObject = jsonResponse.toString();


//                String -> bytes
                byte[] bytesUpdatedJsonString = newStringJsonAttObject.getBytes();

//                bytes -> AttestationObject (HERE PROBLEMO)
//                AttestationObject asd = jsonConverter.readValue(newStringJsonAttObject);
                AttestationObject newAttestObj = attestationObjectConverter.convert(bytesUpdatedJsonString);

//                AttestationObject -> (Base64 URL encoded) String
                String finalEncodedAttestationObject = attestationObjectConverter.convertToBase64urlString(newAttestObj);

                logging.logToOutput("ok");

//                byte[] newCborArray = Base64.getUrlEncoder().encode(newAttestObj);

//                String attestationObject = parameter.value();
//                byte[] cborArray = Base64.getUrlDecoder().decode(attestationObject);
//
//                AttestationObject newAttestationObject = Base64.getUrlEncoder().encode();



                byte[] updatedCborArray = cborArray.clone();
//                updatedCborArray[62] = 64;
                String updatedParameterValue = new String(Base64.getUrlEncoder().encode(updatedCborArray));




        return request;

    }

    private HttpRequest testDemoYubico(HttpRequest request) {

        if (!request.method().equals("POST")) {
            return request;
        }

        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
//        AttestationObject attestationObject = null;
//        byte[] rpIdHash = null;

        if (request.url().equals("https://demo.yubico.com/api/v1/simple/webauthn/register-finish")) {
            JSONObject body = new JSONObject(request.body().toString());

//            Util.changeUPJson(body);

//            String encodedAttestationObject = body.getJSONObject("attestation").get("attestationObject").toString();
//            byte[] cborArray = Base64.getDecoder().decode(encodedAttestationObject);
//            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

//            attestationObject = attestationObjectConverter.convert(cborArray);
//            rpIdHash = attestationObject.getAuthenticatorData().getRpIdHash();

//            Assumption: hash is unique
//            int index = Util.findSubarrayIndex(rpIdHash, cborArray);

//            change values
//            byte flags = cborArray[index + rpIdHash.length];
//            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111110);

//            String newEncodedAttestationObject = new String(Base64.getEncoder().encode(cborArray));
//            byte[] newCbor = Base64.getDecoder().decode(newEncodedAttestationObject); // just for debugging

//            body.getJSONObject("attestation").put("attestationObject", newEncodedAttestationObject);

//            return request.withBody(body.toString());
            return request;
        }

        if (request.url().equals("https://demo.yubico.com/api/v1/simple/webauthn/authenticate-finish")) {
            //            Get request's original body
            JSONObject body = new JSONObject(request.body().toString());


            try {

//                Util.changeUPJson(body);

//            Extract relevant values
                String clientData = body.getJSONObject("assertion").get("clientDataJSON").toString();
                String authenticatorData = body.getJSONObject("assertion").get("authenticatorData").toString();
                String origSignature = body.getJSONObject("assertion").get("signature").toString();
                byte[] decodedSignature = Base64.getDecoder().decode(origSignature);

//                SHA256 of the clientDataJSON
                String clientDataJSON = new String(Base64.getDecoder().decode(clientData));
                byte[] clientDataBytes = clientDataJSON.getBytes();
                byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);
//                Decode authenticatorData
                byte[] decodedAuthenticatorData = Base64.getDecoder().decode(authenticatorData);
                String hexCborArray = Util.bytesToHex(decodedAuthenticatorData); // just to print out hex

//            Modify authenticatorData (e.g., userPresence 1 -> 0)
//            https://w3c.github.io/webauthn/#authenticator-data
//                Assumption: hash is unique
                int index = Util.findSubarrayIndex(decodedAuthenticatorData, rpIdHash);
                byte flags = decodedAuthenticatorData[index + rpIdHash.length];
                decodedAuthenticatorData[index + rpIdHash.length] = (byte) (flags & 0b11111110);

//                byte[] payload = (authenticatorData + clientDataHash).getBytes(StandardCharsets.UTF_8);
//                byte[] payload = Base64.getDecoder().decode(authenticatorData + clientDataHash);

//            https://w3c.github.io/webauthn/#sctn-op-get-assertion
//            Concatenate two values and create assertion signature
                ByteArrayOutputStream concatenatedByteArray = new ByteArrayOutputStream();
                concatenatedByteArray.write(decodedAuthenticatorData);
                concatenatedByteArray.write(clientDataHash);
                byte[] data = concatenatedByteArray.toByteArray();

//                Get private key
                PrivateKey privateKey = Util.getPrivateKey("/Users/pchen/Downloads/Private key.pem");
//                System.out.println(privateKey);

//                Sign new data
//            Check signature format
//            https://w3c.github.io/webauthn/#sctn-signature-attestation-types
                byte[] signature = Util.sign(body, data, privateKey);

                PublicKey publicKey = Util.getPublicKey("/Users/pchen/Downloads/Public key.pem");
//                Verifying my signature
                boolean verified = Util.verify(data, signature, publicKey);
                assert verified;
//                Verifying the original signature
                boolean verifyOriginal = Util.verify(data, decodedSignature, publicKey);
                assert verifyOriginal;
//
//                Encode signature
                byte[] encodedSignature = Base64.getEncoder().encode(signature);
                String stringSignature = new String(encodedSignature);
//                Encode original signature
                byte[] encodedOriginalSignature = Base64.getEncoder().encode(decodedSignature);
                String stringOriginalSignature = new String(encodedOriginalSignature);

//                Update data in the body
                body.getJSONObject("assertion").put("signature", stringSignature);
//                body.getJSONObject("assertion").put("signature", stringOriginalSignature);
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
//            byte[] test = "1".getBytes();
//            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(test); // 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b

//            Return updated request
            return request.withBody(body.toString());
        }

        return request;
    }

    private HttpRequest testDemoQuado(HttpRequest request) {

        if (!request.method().equals("PATCH")) {
            return request;
        }

        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
//        AttestationObject attestationObject = null;
//        byte[] rpIdHash = null;

        if (request.url().equals("https://api.quado.io/webauthn/api/v1/registrations")) {
            JSONObject body = new JSONObject(request.body().toString());

            String encodedAttestationObject = body.getJSONObject("fido_response").getJSONObject("response").get("attestationObject").toString();
            byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
            String hexCborArray = Util.bytesToHex(cborArray); // just to print out hex

            attestationObject = attestationObjectConverter.convert(cborArray);
            rpIdHash = attestationObject.getAuthenticatorData().getRpIdHash();

//            Assumption: hash is unique
            int index = Util.findSubarrayIndex(cborArray, rpIdHash);

//            change values
            byte flags = cborArray[index + rpIdHash.length];
            cborArray[index + rpIdHash.length] = (byte) (flags & 0b11111110);

            String newEncodedAttestationObject = new String(Base64.getUrlEncoder().encode(cborArray));
            byte[] newCbor = Base64.getUrlDecoder().decode(newEncodedAttestationObject); // just for debugging

//            TODO (ATTESTATION STATEMENT -> RECOMPUTE SIGNATURE)
            body.getJSONObject("fido_response").getJSONObject("response").put("attestationObject", newEncodedAttestationObject.replace("=", ""));
//            body.getJSONObject("fido_response").getJSONObject("response").put("attestationObject", new String(Base64.getUrlEncoder().encode(Base64.getUrlDecoder().decode(encodedAttestationObject))).replace("=", ""));

            //    "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAOYbVf07-U6Vt9rjk4nwVRdLTLsWuW2Uj78Y9Y_4De5sAiBjkIbCLrAPgonkyvZaXCEjGTx8lv9GlAOcNzP80Bh7EGN4NWOBWQHeMIIB2jCCAX2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQzMDkyMTA5MzYzMlowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB_wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCAwgwDQYJKoZIhvcNAQELBQADSAAwRQIgC2jFjOPHUS0hWZBm4ICJ7ypaauKNXGyHDIzuLibqFLMCIQCxanjwieb5KkgKIGDNDY1_1ifro4t9t68WAN0PSwcqy2hhdXRoRGF0YVikE4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJNBAAAAAQECAwQFBgcIAQIDBAUGBwgAIGXgDv-NE-gVdLD5Z9Pq2fRRIb29OYrLKCeHSOh6zZFNpQECAyYgASFYIKk_45uDRIDPGBFppEVX6VqettNf-d3Dhwr5_aXYuig_Ilggg2YzbSBvy-16snN4-Lf3K0m4LQyNITQWHYXKmzMWi8I"
            //    "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAOYbVf07-U6Vt9rjk4nwVRdLTLsWuW2Uj78Y9Y_4De5sAiBjkIbCLrAPgonkyvZaXCEjGTx8lv9GlAOcNzP80Bh7EGN4NWOBWQHeMIIB2jCCAX2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQzMDkyMTA5MzYzMlowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB_wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCAwgwDQYJKoZIhvcNAQELBQADSAAwRQIgC2jFjOPHUS0hWZBm4ICJ7ypaauKNXGyHDIzuLibqFLMCIQCxanjwieb5KkgKIGDNDY1_1ifro4t9t68WAN0PSwcqy2hhdXRoRGF0YVikE4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJNAAAAAAQECAwQFBgcIAQIDBAUGBwgAIGXgDv-NE-gVdLD5Z9Pq2fRRIb29OYrLKCeHSOh6zZFNpQECAyYgASFYIKk_45uDRIDPGBFppEVX6VqettNf-d3Dhwr5_aXYuig_Ilggg2YzbSBvy-16snN4-Lf3K0m4LQyNITQWHYXKmzMWi8I="


            return request.withBody(body.toString());
        }

        if (request.url().equals("https://api.quado.io/webauthn/api/v1/authentications")) {
            //            Get request's original body
            JSONObject body = new JSONObject(request.body().toString());

//            Extract relevant values
            String clientData = body.getJSONObject("assertion").get("clientDataJSON").toString();
            String authenticatorData = body.getJSONObject("assertion").get("authenticatorData").toString();
            String origSignature = body.getJSONObject("assertion").get("signature").toString();
            byte[] decodedSignature = Base64.getDecoder().decode(origSignature);


            try {
//                SHA256 of the clientDataJSON
                String clientDataJSON = new String(Base64.getDecoder().decode(clientData));
                byte[] clientDataBytes = clientDataJSON.getBytes();
                byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);
//                Decode authenticatorData
                byte[] decodedAuthenticatorData = Base64.getDecoder().decode(authenticatorData);
                String hexCborArray = Util.bytesToHex(decodedAuthenticatorData); // just to print out hex

//            Modify authenticatorData (e.g., userPresence 1 -> 0)
//            https://w3c.github.io/webauthn/#authenticator-data
//                Assumption: hash is unique
                int index = Util.findSubarrayIndex(decodedAuthenticatorData, rpIdHash);
                byte flags = decodedAuthenticatorData[index + rpIdHash.length];
                decodedAuthenticatorData[index + rpIdHash.length] = (byte) (flags & 0b11111110);

//                byte[] payload = (authenticatorData + clientDataHash).getBytes(StandardCharsets.UTF_8);
//                byte[] payload = Base64.getDecoder().decode(authenticatorData + clientDataHash);

//            https://w3c.github.io/webauthn/#sctn-op-get-assertion
//            Concatenate two values and create assertion signature
                ByteArrayOutputStream concatenatedByteArray = new ByteArrayOutputStream();
                concatenatedByteArray.write(decodedAuthenticatorData);
                concatenatedByteArray.write(clientDataHash);
                byte[] data = concatenatedByteArray.toByteArray();

//                Get private key
                PrivateKey privateKey = Util.getPrivateKey("/Users/pchen/Downloads/Private key.pem");
//                System.out.println(privateKey);

//                Sign new data
//            Check signature format
//            https://w3c.github.io/webauthn/#sctn-signature-attestation-types
                byte[] signature = Util.sign(body, data, privateKey);

                PublicKey publicKey = Util.getPublicKey("/Users/pchen/Downloads/Public key.pem");
//                Verifying my signature
                boolean verified = Util.verify(data, signature, publicKey);
                assert verified;
//                Verifying the original signature
                boolean verifyOriginal = Util.verify(data, decodedSignature, publicKey);
                assert verifyOriginal;
//
//                Encode signature
                byte[] encodedSignature = Base64.getEncoder().encode(signature);
                String stringSignature = new String(encodedSignature);
//                Encode original signature
                byte[] encodedOriginalSignature = Base64.getEncoder().encode(decodedSignature);
                String stringOriginalSignature = new String(encodedOriginalSignature);

//                Update data in the body
                body.getJSONObject("assertion").put("signature", stringSignature);
//                body.getJSONObject("assertion").put("signature", stringOriginalSignature);
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
//            byte[] test = "1".getBytes();
//            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(test); // 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b

//            Return updated request
            return request.withBody(body.toString());
        }

        return request;
    }

    private HttpRequest testAuth0(HttpRequest request) {

        if (!request.method().equals("POST")) {
            return request;
        }

        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);

        if (request.url().contains("enrollment")) {
            List<ParsedHttpParameter> parameters = request.parameters();
            String response = null;
            for (ParsedHttpParameter parameter : parameters) {
                if (parameter.name().equals("response")) {
                    response = parameter.value();
                    String urlDecodedResponse = URLDecoder.decode(response, StandardCharsets.UTF_8);
//                    System.out.println(urlDecodedResponse);
                    JSONObject responseJson = new JSONObject(urlDecodedResponse);
                    String encodedAttestationObject = responseJson.getJSONObject("response").get("attestationObject").toString();
//                    System.out.println("attestationObject = " + encodedAttestationObject);
                    byte[] decodedAttestationObject = Base64.getUrlDecoder().decode(encodedAttestationObject);
//                    System.out.println(decodedAttestationObject);

                    attestationObject = attestationObjectConverter.convert(decodedAttestationObject);
                    rpIdHash = attestationObject.getAuthenticatorData().getRpIdHash();

//                    Assumption: hash is uniquex
                    int index = Util.findSubarrayIndex(decodedAttestationObject, rpIdHash);

//                    change values
                    byte flags = decodedAttestationObject[index + rpIdHash.length];
                    decodedAttestationObject[index + rpIdHash.length] = (byte) (flags & 0b11111110);

                    String newEncodedAttestationObject = new String(Base64.getUrlEncoder().encode(decodedAttestationObject));
                    byte[] newCbor = Base64.getUrlDecoder().decode(newEncodedAttestationObject); // just for debugging

                    responseJson.getJSONObject("response").put("attestationObject", newEncodedAttestationObject);
                    String newUrlEncodedResponse = URLEncoder.encode(responseJson.toString(), StandardCharsets.UTF_8);

                    HttpParameter newParameter = new HttpParameter() {
                        @Override
                        public HttpParameterType type() {
                            return HttpParameterType.BODY;
                        }

                        @Override
                        public String name() {
                            return "response";
                        }

                        @Override
                        public String value() {
                            return newUrlEncodedResponse;
                        }
                    };
                    return request.withParameter(newParameter);

                }
            }
        }

        return request;
    }

*/
}

