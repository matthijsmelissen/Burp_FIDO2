package com.burp.Tests;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.burp.Const;
import com.burp.Util.Util;
import org.json.JSONObject;

import java.util.Base64;
import java.util.List;

public class AttestationRpIdHashTest extends WebAuthnTest{
    public AttestationRpIdHashTest(MontoyaApi api, String testType) {
        this.api = api;
        this.testName = "RP Id Hash";
        this.testType = testType;
    }

    /**
     * @param request
     * @return
     */
    @Override
    public HttpResponse execute(HttpRequest request) {

        String encodedAttestationObject = Util.getAttestationObject(request);
        byte[] rpIdHash = Util.getRpIdHash(encodedAttestationObject);

//        cborArray
        byte[] cborArray = Base64.getUrlDecoder().decode(encodedAttestationObject);
        String hexCborArray = Util.bytesToHex(cborArray); // get hex values for debugging

//        Find index of the rpIdHash bytes in the attestationObject/cborArray
        int rpIdHashIndex = Util.findSubarrayIndex(cborArray, rpIdHash);
//        Copy the original rpIdHash with "Test Extension"
        System.arraycopy(Const.TEST_EXTENSION.getBytes(), 0, cborArray, rpIdHashIndex, Const.TEST_EXTENSION.getBytes().length);
//        Encode the cborArray back to new attestation object
        String newAttestationObject = Util.base64UrlEncode(cborArray);

//        Special discord case
        if (request.url().toLowerCase().contains("discord".toLowerCase())) {
            JSONObject jsonBody = new JSONObject(request.bodyToString());
            JSONObject credentialJSON = new JSONObject(jsonBody.getString("credential"));
            Util.setValueInJsonRecursively(credentialJSON, Const.ATTESTATION_OBJECT, newAttestationObject);
            jsonBody = jsonBody.put("credential", credentialJSON.toString());
            request = request.withBody(jsonBody.toString());
            return api.http().sendRequest(request).response();
        }

        request = Util.setAttestationObject(request, newAttestationObject);

        return api.http().sendRequest(request).response();

    }

}
