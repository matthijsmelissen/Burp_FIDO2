package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;

public class CredentialPublicKeyTest extends WebAuthnTest {
    public CredentialPublicKeyTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "Credential Public Key";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {
//        https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples


            String encodedAttestationObject = Util.getAttestationObject(request);
            byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);

//        WE ASSUME FOR NOW THAT ES256 IS ALWAYS USED
//        WE TRY TO CHANGE TO ALG HERE
//            https://www.iana.org/assignments/cose/cose.xhtml
//            https://cbor.me/ -> put alg identifier that you want -> CBOR encode it
            int algIndex = Util.findSubarrayIndex(cborArray, new byte[]{0x1, 0x2, 0x3, 0x26});

//        Change alg to another one
            cborArray[algIndex + 3] = (byte) (37);

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

//            DEBUG
//        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
//        ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
//        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
//        attestationObject = attestationObjectConverter.convert(cborArray);
//        COSEKey key = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
//        System.out.println(key.getAlgorithm());
//        System.out.println(attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid());
//        System.out.println(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId());


        return api.http().sendRequest(request).response();
    }


}
