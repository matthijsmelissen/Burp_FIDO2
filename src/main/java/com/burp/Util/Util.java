package com.burp.Util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.burp.Const;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Util {
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 3];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = HEX_ARRAY[v >>> 4];
            hexChars[j * 3 + 1] = HEX_ARRAY[v & 0x0F];
            hexChars[j * 3 + 2] = (byte) ' ';
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    private static String getPemFile(String path) {
        String pem;

        StringBuilder strKeyPEM = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(path));
            String line;
            while ((line = br.readLine()) != null) {
                strKeyPEM.append(line).append("\n");
            }
            br.close();
            pem = strKeyPEM.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return pem;
    }

    private static String stripPemFile(String pemFile) {
        return pemFile
                .replaceAll("\n", "")
                .replaceAll(" ", "")
                .replaceAll("-{5}[a-zA-Z]*-{5}", "");
    }

    public static PrivateKey getPrivateKey(String path) {
        // Read key from file
        String pemFile = getPemFile(path);

        String encodedPrivateKey = stripPemFile(pemFile);
        byte[] decodedPem = Base64.getDecoder().decode(encodedPrivateKey);

        PrivateKey privateKey;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPem);

            privateKey = keyFactory.generatePrivate(keySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

//        Compare with openssl ec -in Private\ key.pem -outform PEM -text -noout
//        Private-Key: (256 bit)
//        priv:
//        53:1a:52:cd:70:b0:6c:48:cf:27:2e:31:a6:1f:cc:
//        d8:86:58:e4:d0:b0:c1:b7:e4:67:39:26:b5:96:52:
//        04:d5
//        pub:
//        04:b1:17:d0:cb:79:ee:08:1a:78:7c:3a:41:45:8c:
//        4b:0e:5d:ed:4d:93:04:b6:a2:0a:b3:9d:e8:23:9e:
//        9d:a0:bc:a4:b9:38:da:9d:00:ea:77:3d:e5:59:e5:
//        d2:41:f0:50:94:b1:56:35:69:26:a6:ff:4c:94:6b:
//        84:15:a2:c7:1b
//        ASN1 OID: prime256v1
//        NIST CURVE: P-256
        return privateKey;
    }

    public static PublicKey getPublicKey(String path) {
        String pemFile = getPemFile(path);

        String encodedPublicKey = stripPemFile(pemFile);
        byte[] decodedPem = Base64.getDecoder().decode(encodedPublicKey);

        PublicKey publicKey;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPem);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPem);

            publicKey = keyFactory.generatePublic(keySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return publicKey;
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) {
//        TestDataUtil.calculateSignature(selectedCredential.getPrivateKey().getPrivateKey(), data);

        byte[] signatureBytes = null;
        try {
//            Get signature instance and initialize with private key
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(privateKey);

            ecdsa.update(data);
//            Create assertion signature
            signatureBytes = ecdsa.sign();

//            ********
//            PublicKey publicKey = getPublicKey("/Users/pchen/Downloads/Public key.pem");
//            Verify my new signature
//            boolean verified = verify(data, signatureBytes, publicKey);
//            Verify original signature
//            boolean verifyOriginal = Util.verify(data, decodedSignature, publicKey);

//            Encode my new signature
//            byte[] encodedSignature = Base64.getUrlEncoder().encode(signatureBytes);
//            String stringSignature = new String(encodedSignature);
//            Encode original signature
//            byte[] encodedOriginalSignature = Base64.getUrlEncoder().encode(decodedSignature);
//            String stringOriginalSignature = new String(encodedOriginalSignature);

            return signatureBytes;

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            System.out.println(e.getMessage());
        }

        return signatureBytes;
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        Signature verifier;
        try {
            verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);

            verifier.update(data);
            return verifier.verify(signature);

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            System.out.println(e.getMessage());
        }

        return false;
    }

    public static int findSubarrayIndex(byte[] cborArray, byte[] bytesToBeFound) {
        if (bytesToBeFound == null || cborArray == null || bytesToBeFound.length == 0 || cborArray.length == 0) {
            return -1; // Handle edge cases
        }

        for (int i = 0; i <= cborArray.length - bytesToBeFound.length; i++) {
            boolean found = true;
            for (int j = 0; j < bytesToBeFound.length; j++) {
                if (bytesToBeFound[j] != cborArray[i + j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i; // Return the index where bytesToBeFound is found as a subarray in cborArray
            }
        }

        return -1; // If bytesToBeFound is not found as a subarray in cborArray
    }

//    Case-insensitive
    public static Object getKeyInJsonRecursively(JSONObject jsonObject, String keyToBeFound) {
        Object value = null;

        for (String key : jsonObject.keySet()) {
            if (keyToBeFound.equalsIgnoreCase(key)) {
                return jsonObject.get(key);
            } else {
//                if (key.equalsIgnoreCase("credential") && keyToBeFound.equalsIgnoreCase(Const.ATTESTATION_OBJECT)) {
//                    JSONObject test = new JSONObject(jsonObject.get("credential"));
//                    JSONObject test2 = new JSONObject((String) jsonObject.get("credential"));
//                    System.out.println("aSd");
//                }
                if (jsonObject.get(key) instanceof String) {
                    String stringValue = (String) jsonObject.get(key);
                    if (isJson(stringValue)) {
                        JSONObject nestedJsonObject = new JSONObject(stringValue);
                        value = getKeyInJsonRecursively(nestedJsonObject, keyToBeFound);
//                        value = getKeyInJsonRecursively((JSONObject) jsonObject.get(key), keyToBeFound);
                    }
                } else if (jsonObject.get(key) instanceof JSONObject) {
                    value = getKeyInJsonRecursively((JSONObject) jsonObject.get(key), keyToBeFound);
                }

                if (value != null) {
                    return value;
                }
            }
        }

        return value;
    }


    //    Case-insensitive
    public static void setValueInJsonRecursively(JSONObject jsonObject, String keyToBeFound, String valueToBeSet) {

//        TODO: change valueToBeSet's type to Object

        for (String key : jsonObject.keySet()) {
            Object jsonValue = jsonObject.get(key);

            if (keyToBeFound.equalsIgnoreCase(key)) {
                try {
//                    To change "publicKeyAlgorithm":-7 -> -260 e.g.
                    int intValue = Integer.parseInt(valueToBeSet);
                    jsonObject.put(key, intValue);
                } catch (Exception e) {
//                    To change attestationObject
                    jsonObject.put(key, valueToBeSet);
                }

            } else if (jsonValue instanceof JSONObject) {
                setValueInJsonRecursively((JSONObject) jsonValue, keyToBeFound, valueToBeSet);
            }
//            else if (jsonValue instanceof String) {
//                String stringValue = (String) jsonValue;
//                if (isJson(stringValue)) {
//                    JSONObject nestedJsonObject = new JSONObject(stringValue);
//                    setValueInJsonRecursively(nestedJsonObject, keyToBeFound, valueToBeSet);
//                }
//            }
        }
    }

    public static byte[] getRpIdHash(String encodedData) {
        byte[] cborArray = Base64.getUrlDecoder().decode(encodedData);

        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
        try {
            AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
            AttestationObject attestationObject = attestationObjectConverter.convert(cborArray);
            return attestationObject.getAuthenticatorData().getRpIdHash();
        } catch (Exception e) {
            AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
            AuthenticatorData authenticatorData = authenticatorDataConverter.convert(cborArray);
            return authenticatorData.getRpIdHash();
        }
    }

    public static byte[] getRpIdHash(HttpRequest request) {

//        if (request.url().contains("discord")) {
//            request = request.withBody(request.bodyToString().replace("\\\"", "\""));
//        }

        if (request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {

//            String encodedAttestationObject = null;

//            if (isJson(request.bodyToString())) {
//            if (request.contentType().equals(ContentType.JSON)) {
//                JSONObject body = new JSONObject(request.bodyToString());
//                encodedAttestationObject = (String) getKeyInJsonRecursively(body, Const.ATTESTATION_OBJECT);
//            } else {
//                for (HttpParameter parameter : request.parameters()) {
//                    if (parameter.name().equalsIgnoreCase(Const.ATTESTATION_OBJECT)) {
//                        encodedAttestationObject = parameter.value();
//                    }
//                }
//            }

            String encodedAttestationObject = getAttestationObject(request);

//            byte[] cborArray = null;
//            try {
//                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
//            } catch (IllegalArgumentException e) {
//                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
//            }

            byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
            String hexCborArray = bytesToHex(cborArray); // just to print out hex

            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
            AttestationObject attestationObject = attestationObjectConverter.convert(cborArray);

            return attestationObject.getAuthenticatorData().getRpIdHash();
        } else if (request.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {
//            String encodedAuthenticatorData = null;
//
//            if (isJson(request.bodyToString())) {
//                JSONObject body = new JSONObject(request.bodyToString());
//                encodedAuthenticatorData = (String) getKeyInJsonRecursively(body, Const.AUTHENTICATOR_DATA);
//            } else {
//                for (HttpParameter parameter : request.parameters()) {
//                    if (parameter.name().equalsIgnoreCase(Const.AUTHENTICATOR_DATA)) {
//                        encodedAuthenticatorData = parameter.value();
//                    }
//                }
//            }

            String encodedAuthenticatorData = getAuthenticatorData(request);

//            byte[] cborArray = null;
//            try {
//                cborArray = Base64.getUrlDecoder().decode(encodedAuthenticatorData);
//            } catch (IllegalArgumentException e) {
//                cborArray = Base64.getDecoder().decode(encodedAuthenticatorData);
//            }

            byte[] cborArray = Base64.getUrlDecoder().decode(encodedAuthenticatorData);
            String hexCborArray = bytesToHex(cborArray); // just to print out hex

            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
            AuthenticatorData authenticatorData = authenticatorDataConverter.convert(cborArray);

            return authenticatorData.getRpIdHash();
        }

        try {
            return MessageDigest.getInstance("SHA-256").digest(request.headerValue("Host").getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



  /*  public static byte[] getCredentialId(HttpRequest request) {
        if (request.bodyToString().toLowerCase().contains(Const.ATTESTATION_OBJECT.toLowerCase())) {

            String encodedAttestationObject = null;

//            if (isJson(request.bodyToString())) {
            if (request.contentType().equals(ContentType.JSON)) {
                JSONObject body = new JSONObject(request.bodyToString());
                encodedAttestationObject = (String) getKeyInJsonRecursively(body, Const.ATTESTATION_OBJECT);
            } else {
                for (HttpParameter parameter : request.parameters()) {
                    if (parameter.name().equalsIgnoreCase(Const.ATTESTATION_OBJECT)) {
                        encodedAttestationObject = parameter.value();
                    }
                }
            }

            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAttestationObject);
            }

            String hexCborArray = bytesToHex(cborArray); // just to print out hex

            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
            AttestationObject attestationObject = attestationObjectConverter.convert(cborArray);

            return attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        } else if (request.bodyToString().toLowerCase().contains(Const.AUTHENTICATOR_DATA.toLowerCase())) {
            String encodedAuthenticatorData = null;

//            if (isJson(request.bodyToString())) {
            if (request.contentType().equals(ContentType.JSON)) {
                JSONObject body = new JSONObject(request.bodyToString());
                encodedAuthenticatorData = (String) getKeyInJsonRecursively(body, Const.AUTHENTICATOR_DATA);
            } else {
                for (HttpParameter parameter : request.parameters()) {
                    if (parameter.name().equalsIgnoreCase(Const.AUTHENTICATOR_DATA)) {
                        encodedAuthenticatorData = parameter.value();
                    }
                }
            }

            byte[] cborArray = null;
            try {
                cborArray = Base64.getUrlDecoder().decode(encodedAuthenticatorData);
            } catch (IllegalArgumentException e) {
                cborArray = Base64.getDecoder().decode(encodedAuthenticatorData);
            }

            String hexCborArray = bytesToHex(cborArray); // just to print out hex

            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
            AuthenticatorData authenticatorData = authenticatorDataConverter.convert(cborArray);

            return authenticatorData.getAttestedCredentialData().getCredentialId();
        }

        return null;
    }*/


    public static byte[] getCredentialIdFromAttestationObject(String encodedAttestationObject) {
        byte[] cborArray = null;
        try {
            cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
        } catch (IllegalArgumentException e) {
            cborArray = Base64.getDecoder().decode(encodedAttestationObject);
        }

        String hexCborArray = bytesToHex(cborArray); // just to print out hex

        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        AttestationObject attestationObject = attestationObjectConverter.convert(cborArray);

        return attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
    }

    public static String replaceCredIDInAttestationObject(String encodedAttestationObject, byte[] newCredentialId) {
        byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
        String hexCborArray = bytesToHex(cborArray); // just to print out hex

        byte[] credentialId = getCredentialIdFromAttestationObject(encodedAttestationObject);
        String hexCredentialId = bytesToHex(credentialId); // just to print out hex

        int credentialIDIndex = findSubarrayIndex(cborArray, credentialId);

        System.arraycopy(newCredentialId, 0, cborArray, credentialIDIndex, Math.min(credentialId.length, newCredentialId.length));

        return Base64.getUrlEncoder().encodeToString(cborArray).replaceAll("=", "");
    }


    public static boolean isJson(String body) {
        if (body.isEmpty()) return false;
        return body.charAt(0) == '{' && body.charAt(body.length() - 1) == '}';
    }

    public static String recomputeAssertionSignature(HttpRequest request, boolean isUrlEncoding) {

        String clientData = null;
        String authenticatorData = null;
//        String origSignature = null;

        if (request.contentType().equals(ContentType.JSON)) {
            clientData = (String) getKeyInJsonRecursively(new JSONObject(request.bodyToString()), Const.CLIENT_DATA_JSON);
            authenticatorData = (String) getKeyInJsonRecursively(new JSONObject(request.bodyToString()), Const.AUTHENTICATOR_DATA);
//            origSignature = (String) getKeyInJsonRecursively(new JSONObject(request.bodyToString()), Const.SIGNATURE);
        } else {
            clientData = getNameInParameters(request, Const.CLIENT_DATA_JSON).value();
            authenticatorData = getNameInParameters(request, Const.AUTHENTICATOR_DATA).value();
//            origSignature = getKeyInParameters(request, Const.SIGNATURE).value();
        }

        byte[] clientDataBytes = isUrlEncoding ? Base64.getUrlDecoder().decode(clientData) : Base64.getDecoder().decode(clientData);
        byte[] decodedAuthenticatorData = isUrlEncoding ? Base64.getUrlDecoder().decode(authenticatorData) : Base64.getDecoder().decode(authenticatorData);

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
            PrivateKey privateKey = getPrivateKey("/Users/pchen/Downloads/Private key.pem");

//        Sign new data (format: https://w3c.github.io/webauthn/#sctn-signature-attestation-types)
            byte[] signature = sign(data, privateKey);

            //            setValueInJsonRecursively(requestBody, Const.SIGNATURE, encodedSignature.replace("=", ""));
            return isUrlEncoding ? Base64.getUrlEncoder().encodeToString(signature).replace("=", "") : Base64.getEncoder().encodeToString(signature).replace("=", "");
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }

//        return null;

    }

    public static HttpRequest recomputeAssertionSignature(HttpRequest request) {

        String clientData = getClientData(request);
        String authenticatorData = getAuthenticatorData(request);


        byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientData);
        byte[] decodedAuthenticatorData = Base64.getUrlDecoder().decode(authenticatorData);

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
            PrivateKey privateKey = getPrivateKey("/Users/pchen/Downloads/Private key.pem");

//        Sign new data (format: https://w3c.github.io/webauthn/#sctn-signature-attestation-types)
            byte[] signatureBytes = sign(data, privateKey);
            String signature = Base64.getUrlEncoder().encodeToString(signatureBytes).replace("=", "");
//            String signature = base64UrlEncode(Arrays.toString(signatureBytes));


    //            setValueInJsonRecursively(requestBody, Const.SIGNATURE, encodedSignature.replace("=", ""));
            return setSignature(request, signature);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }

//        return null;

    }

    public static void createAlgsIssue(int nonRecommendedAlg, String host, MontoyaApi api) {




    }


//    TODO remove this
//    public static int getSignCount(HttpRequest request, byte[] rpIdHash) {
//
//        String authenticatorData = null;
//
//        if (request.contentType().equals(ContentType.JSON)) {
//            authenticatorData = (String) getKeyInJsonRecursively(new JSONObject(request.bodyToString()), Const.AUTHENTICATOR_DATA);
//        } else {
//            authenticatorData = getNameInParameters(request, Const.AUTHENTICATOR_DATA).value();
//        }
//
//        byte[] cborArray = null;
//        try {
//            cborArray = Base64.getUrlDecoder().decode(authenticatorData);
//        } catch (IllegalArgumentException e) {
//            cborArray = Base64.getDecoder().decode(authenticatorData);
//        }
////        String hexCborArray = bytesToHex(cborArray); // just to print out hex
//
////        Assumption: hash is unique
//        int index = findSubarrayIndex(cborArray, rpIdHash);
//
//        byte[] signCountBytes = new byte[4];
//        for (int i = 0; i < 4; i++) {
//            signCountBytes[i] = cborArray[index + rpIdHash.length + 1 + i];
//        }
//        return ByteBuffer.wrap(signCountBytes).getInt();
//    }

    public static int getSignCount(HttpRequest request) {

        byte[] rpIdHash = getRpIdHash(request);
        String authenticatorData = getAuthenticatorData(request);
        byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);

        int indexSignCounter = findSubarrayIndex(cborArray, rpIdHash) + rpIdHash.length + 1;

//        Get sign count as 4 bytes-array
        byte[] signCountBytes = new byte[4];
        System.arraycopy(cborArray, indexSignCounter, signCountBytes, 0, 4);
//        Return the int value
        return ByteBuffer.wrap(signCountBytes).getInt();
    }


    public static String changeSignCount(String authenticatorData, int newSignCount, byte[] rpIdHash) {
        boolean isUrlEncoding;
        byte[] cborArray = null;
        try {
            cborArray = Base64.getUrlDecoder().decode(authenticatorData);
            isUrlEncoding = true;
        } catch (IllegalArgumentException e) {
            cborArray = Base64.getDecoder().decode(authenticatorData);
            isUrlEncoding = false;
        }

        int index = Util.findSubarrayIndex(cborArray, rpIdHash);

        byte[] signCountBytes = ByteBuffer.allocate(4).putInt(newSignCount).array();
        for (int i = 0; i < 4; i++) {
            cborArray[index + rpIdHash.length + 1 + i] = signCountBytes[i];
        }

        String newAuthenticatorData = isUrlEncoding ? Base64.getUrlEncoder().encodeToString(cborArray) : Base64.getEncoder().encodeToString(cborArray);

        return newAuthenticatorData.replace("=", "");
    }

/*    public static String changeSignCount(String authenticatorData, int newSignCount) {
        byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);

        int index = Util.findSubarrayIndex(cborArray, rpIdHash);

        byte[] signCountBytes = ByteBuffer.allocate(4).putInt(newSignCount).array();
        for (int i = 0; i < 4; i++) {
            cborArray[index + rpIdHash.length + 1 + i] = signCountBytes[i];
        }

        String newAuthenticatorData = isUrlEncoding ? Base64.getUrlEncoder().encodeToString(cborArray) : Base64.getEncoder().encodeToString(cborArray);

        return newAuthenticatorData.replace("=", "");
    }*/


    public static String getPathFromURI(String uriString) {
        try {
            URI uri = new URI(uriString);
            String path = uri.getRawPath();
            String query = uri.getRawQuery();

            return query != null ? path + "?" + query : path;
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static String updateChallengeInClientData(String clientDataJSON, String newChallenge) {
//        Decode client data
        String clientDataString = new String(Base64.getUrlDecoder().decode(clientDataJSON));
//        Create JSON
        JSONObject clientData = new JSONObject(clientDataString);
//        Insert new challenge in JSON
        clientData.put("challenge", newChallenge);
//        Return encoded client data
//        return Base64.getUrlEncoder().encodeToString(clientData.toString().getBytes()).replaceAll("=", "");
        return base64UrlEncode(clientData.toString());
    }


    public static HttpParameter getNameInParameters(HttpRequest request, String key) {
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.name().equalsIgnoreCase(key)) {
                return parameter;
            }
        }
        return null;
    }

    public static HttpParameter getValueInParameters(HttpRequest request, String key) {
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.value().toLowerCase().contains(key.toLowerCase())) {
                return parameter;
            }
        }
        return null;
    }


//    public static HttpParameter setNewValueToParameter(HttpParameter parameter, String newValue) {

//        return HttpParameter.parameter(parameter.name(), newValue, parameter.type());
//    }

    public static HttpRequest setNewValueToParameter(HttpRequest request, String parameterName, String newValue) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, parameterName, newValue);
            return request.withBody(jsonBody.toString());
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            HttpParameter parameter = Util.getNameInParameters(request, parameterName);
            HttpParameter newParameter = HttpParameter.parameter(parameter.name(), newValue, parameter.type());
            return request.withUpdatedParameters(newParameter);
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
            HttpParameter parameter = Util.getValueInParameters(request, parameterName);
//            Assume the content is JSON (only GitHub for now)
            JSONObject jsonParameter = new JSONObject(parameter.value());
            setValueInJsonRecursively(jsonParameter, parameterName, newValue);
            HttpParameter newParameter = HttpParameter.parameter(parameter.name(), jsonParameter.toString(), parameter.type());
            return request.withUpdatedParameters(newParameter);
        }

        return null;
    }

//    public static HttpRequest addParameterInRequest(HttpRequest request, HttpParameter kcActionParameter) {
//        return request.withParameter(kcActionParameter);
//    }


    public static boolean requestFailed(HttpResponse response) {
//        TODO: exclude naive test
//        return response.bodyToString().toLowerCase().contains("fail") ||
//                response.bodyToString().toLowerCase().contains("error") ||
//                response.statusCode() >= 400;
        return (
                response.statusCode() >= 400 ||
                response.contains("flash-error", false) || // github case
                response.contains("security_key_login_failed", false) || // docusign case
//                response.contains("/error?aspxerrorpath", false) // docusign case
                response.contains("security_key_login_failed", false) // docusign demo case
        );
    }

    public static void displayIssues(MontoyaApi api, ArrayList<AuditIssue> issues) {
        for (AuditIssue issue : issues) {
            api.siteMap().add(issue);
        }
    }

    public static String getAttestationObject(HttpRequest request) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            return (String) getKeyInJsonRecursively(jsonBody, Const.ATTESTATION_OBJECT);
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            HttpParameter attestationObjectParameter = Util.getNameInParameters(request, Const.ATTESTATION_OBJECT);
            if (attestationObjectParameter != null) {
                return attestationObjectParameter.value();
            } else {
                return null;
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains attestationObject
            HttpParameter attestationObjectParameter = Util.getValueInParameters(request, Const.ATTESTATION_OBJECT);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(attestationObjectParameter.value());
            return (String) getKeyInJsonRecursively(jsonParameter, Const.ATTESTATION_OBJECT);
        }

        return null;
    }

    public static HttpRequest setAttestationObject(HttpRequest request, String newAttestationObject) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, Const.ATTESTATION_OBJECT, newAttestationObject);
            return request.withBody(jsonBody.toString());
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            HttpParameter attestationObjectParameter = Util.getNameInParameters(request, Const.ATTESTATION_OBJECT);
            HttpParameter newAttestationObjectParameter = HttpParameter.parameter(attestationObjectParameter.name(), newAttestationObject, attestationObjectParameter.type());
            return request.withUpdatedParameters(newAttestationObjectParameter);
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains attestationObject
            HttpParameter attestationObjectParameter = Util.getValueInParameters(request, Const.ATTESTATION_OBJECT);
//            Assume the content is JSON (only GitHub for now)
            JSONObject jsonParameter = new JSONObject(attestationObjectParameter.value());
            setValueInJsonRecursively(jsonParameter, Const.ATTESTATION_OBJECT, newAttestationObject);
            HttpParameter newAttestationObjectParameter = HttpParameter.parameter(attestationObjectParameter.name(), jsonParameter.toString(), attestationObjectParameter.type());
            return request.withUpdatedParameters(newAttestationObjectParameter);
        }

        return null;
    }

    public static String getAuthenticatorData(HttpRequest request) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            return (String) Util.getKeyInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA);
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            if (Util.getNameInParameters(request, Const.AUTHENTICATOR_DATA) != null) {
                HttpParameter authenticatorDataParameter = Util.getNameInParameters(request, Const.AUTHENTICATOR_DATA);
                if (authenticatorDataParameter != null) {
                    return authenticatorDataParameter.value();
                } else {
                    return null;
                }
            } else if (Util.getValueInParameters(request, Const.AUTHENTICATOR_DATA) != null) {
                HttpParameter parameter = getValueInParameters(request, Const.AUTHENTICATOR_DATA);
//                URL Decode twice for Docusign
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                return (String) getKeyInJsonRecursively(jsonParameter, Const.AUTHENTICATOR_DATA);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains attestationObject
            HttpParameter authenticatorDataParameter = Util.getValueInParameters(request, Const.AUTHENTICATOR_DATA);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(authenticatorDataParameter.value());
            return (String) Util.getKeyInJsonRecursively(jsonParameter, Const.AUTHENTICATOR_DATA);
        }

        return null;
    }

    public static HttpRequest setAuthenticatorData(HttpRequest request, String newAuthenticatorData) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
            return request.withBody(jsonBody.toString());
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            if (Util.getNameInParameters(request, Const.AUTHENTICATOR_DATA) != null) {
                HttpParameter authenticatorDataParameter = Util.getNameInParameters(request, Const.AUTHENTICATOR_DATA);
                HttpParameter newAuthenticatorDataParameter = HttpParameter.parameter(authenticatorDataParameter.name(), newAuthenticatorData, authenticatorDataParameter.type());
                return request.withUpdatedParameters(newAuthenticatorDataParameter);
            } else if (Util.getValueInParameters(request, Const.AUTHENTICATOR_DATA) != null) {
                HttpParameter parameter = getValueInParameters(request, Const.AUTHENTICATOR_DATA);
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                setValueInJsonRecursively(jsonParameter, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
                HttpParameter responseParameter = HttpParameter.parameter(parameter.name(), customURLEncode(request, jsonParameter.toString()), parameter.type());
                return request.withUpdatedParameters(responseParameter);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains authenticatorData
            HttpParameter authenticatorDataParameter = Util.getValueInParameters(request, Const.AUTHENTICATOR_DATA);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(authenticatorDataParameter.value());
            setValueInJsonRecursively(jsonParameter, Const.AUTHENTICATOR_DATA, newAuthenticatorData);
            HttpParameter newAuthenticatorDataParameter = HttpParameter.parameter(authenticatorDataParameter.name(), jsonParameter.toString(), authenticatorDataParameter.type());
            return request.withUpdatedParameters(newAuthenticatorDataParameter);
        }

        return null;
    }

    public static String getClientData(HttpRequest request) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            return (String) Util.getKeyInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON);
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            if (Util.getNameInParameters(request, Const.CLIENT_DATA_JSON) != null) {
                HttpParameter clientDataParameter = Util.getNameInParameters(request, Const.CLIENT_DATA_JSON);
                if (clientDataParameter != null) {
                    return clientDataParameter.value();
                } else {
                    return null;
                }
            } else if (Util.getValueInParameters(request, Const.CLIENT_DATA_JSON) != null) {
                HttpParameter parameter = getValueInParameters(request, Const.CLIENT_DATA_JSON);
//                Decode twice because of Docusign
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                return (String) getKeyInJsonRecursively(jsonParameter, Const.CLIENT_DATA_JSON);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains attestationObject
            HttpParameter clientDataParameter = Util.getValueInParameters(request, Const.CLIENT_DATA_JSON);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(clientDataParameter.value());
            return (String) Util.getKeyInJsonRecursively(jsonParameter, Const.CLIENT_DATA_JSON);
        }

        return null;
    }

    public static HttpRequest setClientData(HttpRequest request, String newClientData) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, Const.CLIENT_DATA_JSON, newClientData);
            return request.withBody(jsonBody.toString());
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            if (Util.getNameInParameters(request, Const.CLIENT_DATA_JSON) != null) {
                HttpParameter clientDataParameter = Util.getNameInParameters(request, Const.CLIENT_DATA_JSON);
                HttpParameter newClientDataParameter = HttpParameter.parameter(clientDataParameter.name(), newClientData, clientDataParameter.type());
                return request.withUpdatedParameters(newClientDataParameter);
            } else if (Util.getValueInParameters(request, Const.CLIENT_DATA_JSON) != null) {
//                "clientDataJSON" is in an url parameter's value: it is in the key of a json object
                HttpParameter parameter = getValueInParameters(request, Const.CLIENT_DATA_JSON);
//                URL Decode twice because of Docusign
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                setValueInJsonRecursively(jsonParameter, Const.CLIENT_DATA_JSON, newClientData);
                HttpParameter newParameter = HttpParameter.parameter(parameter.name(), customURLEncode(request, jsonParameter.toString()), parameter.type());
                return request.withUpdatedParameters(newParameter);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains attestationObject
            HttpParameter clientDataParameter = Util.getValueInParameters(request, Const.CLIENT_DATA_JSON);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(clientDataParameter.value());
            setValueInJsonRecursively(jsonParameter, Const.CLIENT_DATA_JSON, newClientData);
            HttpParameter newClientDataParameter = HttpParameter.parameter(clientDataParameter.name(), jsonParameter.toString(), clientDataParameter.type());
            return request.withUpdatedParameters(newClientDataParameter);
        }

        return null;
    }

    public static HttpRequest setSignature(HttpRequest request, String newSignature) {
        if (request.contentType().equals(ContentType.JSON)) {

            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, Const.SIGNATURE, newSignature);
            return request.withBody(jsonBody.toString());

        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {

            if (Util.getNameInParameters(request, Const.SIGNATURE) != null) {
                HttpParameter signatureParameter = Util.getNameInParameters(request, Const.SIGNATURE);
                HttpParameter newSignatureParameter = HttpParameter.parameter(signatureParameter.name(), newSignature, signatureParameter.type());
                return request.withUpdatedParameters(newSignatureParameter);
            } else if (Util.getValueInParameters(request, Const.SIGNATURE) != null) {
                HttpParameter parameter = getValueInParameters(request, Const.SIGNATURE);
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                setValueInJsonRecursively(jsonParameter, Const.SIGNATURE, newSignature);
//                HttpParameter responseParameter = HttpParameter.parameter(parameter.name(), URLEncoder.encode(jsonParameter.toString(), StandardCharsets.UTF_8), parameter.type());
                HttpParameter responseParameter = HttpParameter.parameter(parameter.name(), customURLEncode(request, jsonParameter.toString()), parameter.type());

//                Special Docusign case
//                if (request.url().equals("https://account.docusign.com/securitykeylogin")) {
//                if (request.url().startsWith("https://account.docusign.com/password?")) {
//                    responseParameter = HttpParameter.parameter(parameter.name(), URLEncoder.encode(URLEncoder.encode(jsonParameter.toString(), StandardCharsets.UTF_8), StandardCharsets.UTF_8), parameter.type());
//                }

                return request.withUpdatedParameters(responseParameter);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {

//            Find the part that contains attestationObject
            HttpParameter signatureParameter = Util.getValueInParameters(request, Const.SIGNATURE);
//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(signatureParameter.value());
            setValueInJsonRecursively(jsonParameter, Const.SIGNATURE, newSignature);
            HttpParameter newSignatureParameter = HttpParameter.parameter(signatureParameter.name(), jsonParameter.toString(), signatureParameter.type());
            return request.withUpdatedParameters(newSignatureParameter);
        }

        return null;
    }

    private static String customURLEncode(HttpRequest request, String responseString) {

        if (!request.url().startsWith("https://account.docusign.com/password?")) {
            return URLEncoder.encode(responseString, StandardCharsets.UTF_8);
        } else {
             return URLEncoder.encode(URLEncoder.encode(responseString, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        }
    }

    public static HttpRequest setIdAndRawId(HttpRequest request, String newIdAndRawId) {
        if (request.contentType().equals(ContentType.JSON)) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            Util.setValueInJsonRecursively(jsonBody, Const.ID, newIdAndRawId);
            Util.setValueInJsonRecursively(jsonBody, Const.RAW_ID, newIdAndRawId);
            return request.withBody(jsonBody.toString());
        } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
            if (Util.getNameInParameters(request, Const.ID) != null) {
                HttpParameter idParameter = Util.getNameInParameters(request, Const.ID);
                HttpParameter rawIdParameter = Util.getNameInParameters(request, Const.RAW_ID);
                HttpParameter newIdParameter = HttpParameter.parameter(idParameter.name(), newIdAndRawId, idParameter.type());
                HttpParameter newRawIdParameter = HttpParameter.parameter(rawIdParameter.name(), newIdAndRawId, rawIdParameter.type());
                return request.withUpdatedParameters(newIdParameter, newRawIdParameter);
            } else if (Util.getValueInParameters(request, Const.RAW_ID) != null) {
                HttpParameter parameter = getValueInParameters(request, Const.RAW_ID);
                JSONObject jsonParameter = new JSONObject(URLDecoder.decode(URLDecoder.decode(parameter.value(), StandardCharsets.UTF_8), StandardCharsets.UTF_8));
                setValueInJsonRecursively(jsonParameter, Const.ID, newIdAndRawId);
                setValueInJsonRecursively(jsonParameter, Const.RAW_ID, newIdAndRawId);
                HttpParameter responseParameter = HttpParameter.parameter(parameter.name(), customURLEncode(request, jsonParameter.toString()), parameter.type());
                return request.withUpdatedParameters(responseParameter);
            }
        } else if (request.contentType().equals(ContentType.MULTIPART)) {
//            Find the part that contains id and rawId
            HttpParameter idParameter = Util.getValueInParameters(request, Const.RAW_ID);
//            Assume that rawId and id are together
//            HttpParameter rawIdParameter = Util.getValueInParameters(request, Const.RAW_ID);

//            Assume the content is JSON (only github for now)
            JSONObject jsonParameter = new JSONObject(idParameter.value());
            setValueInJsonRecursively(jsonParameter, Const.ID, newIdAndRawId);
            setValueInJsonRecursively(jsonParameter, Const.RAW_ID, newIdAndRawId);
            HttpParameter newSignatureParameter = HttpParameter.parameter(idParameter.name(), jsonParameter.toString(), idParameter.type());
            return request.withUpdatedParameters(newSignatureParameter);
        }

        return null;
    }

    public static HttpRequest setSignCount(HttpRequest request, int newSignCount) {
        String authenticatorData = getAuthenticatorData(request);
        byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);
        byte[] rpIdHash = getRpIdHash(request);
        int indexSignCounter = findSubarrayIndex(cborArray, rpIdHash) + rpIdHash.length + 1;

//        Convert new sign count to 4 bytes
        byte[] signCountBytes = ByteBuffer.allocate(4).putInt(newSignCount).array();
//        Replace the old sign count with the new one
        for (int i = 0; i < 4; i++) {
            cborArray[indexSignCounter + i] = signCountBytes[i];
        }
        String newAuthenticatorData = Base64.getUrlEncoder().encodeToString(cborArray).replace("=", "");

        return setAuthenticatorData(request, newAuthenticatorData);
    }

    public static String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().encodeToString(data.getBytes()).replace("=", "");
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data).replace("=", "");
    }

    public static String getCookieToBeSet(HttpResponse response, String cookieName) {
        for (Cookie cookie : response.cookies()) {
            if (cookie.name().equalsIgnoreCase(cookieName)) {
                return cookie.value();
            }
        }
        return null;
    }

    public static String getChallengeFromResponse(HttpResponse response) {
        System.out.println(response.mimeType());
        if (response.mimeType().equals(MimeType.JSON)) {
            return (String) getKeyInJsonRecursively(new JSONObject(response.bodyToString()), Const.CHALLENGE);
        }

//     if (request.contentType().equals(ContentType.JSON)) {
//    } else if (request.contentType().equals(ContentType.URL_ENCODED)) {
//    } else if (request.contentType().equals(ContentType.MULTIPART)) {
//    }
        return null;
    }


    public static List<HttpParameter> getParametersFromCookies(List<Cookie> cookies) {
        List<HttpParameter> cookieParameters = new ArrayList<>();

        for (Cookie cookie : cookies) {
            cookieParameters.add(HttpParameter.parameter(cookie.name(), cookie.value(), HttpParameterType.COOKIE));
        }

        return cookieParameters;
    }


    public static HttpRequest setCookie(HttpRequest request, String cookieName, String cookieValue) {
        return request.withUpdatedParameters(HttpParameter.cookieParameter(cookieName, cookieValue));
    }

    public static HttpRequest updateChallengeInRequest(HttpRequest request, String challenge) {
        String clientData = getClientData(request);
        String newClientData = updateChallengeInClientData(clientData, challenge);
        return setClientData(request, newClientData);
    }
}
