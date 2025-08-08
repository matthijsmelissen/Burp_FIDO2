package com.burp;

import burp.api.montoya.MontoyaApi;
import com.burp.Tests.*;

import java.util.ArrayList;

public class WebauthnTests {

    private final MontoyaApi api;
//    private static byte[] rpIdHash;
    private final ArrayList<WebAuthnTest> registrationTests;
    private final ArrayList<WebAuthnTest> authenticationTests;

    public WebauthnTests(MontoyaApi api) {
        this.api = api;
        this.registrationTests = new ArrayList<>();
        this.authenticationTests = new ArrayList<>();

//        Comment or un-comment the tests you (don't) want to execute

//        REGISTRATION TESTS
        registrationTests.add(new NaiveTest(this.api, WebAuthnTestType.REGISTRATION));
        registrationTests.add(new ClientDataCreateTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataChallengeTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataOriginTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataOriginSubdomainTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new AttestationRpIdHashTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new UserPresenceTest(this.api, WebAuthnTestType.REGISTRATION));
        registrationTests.add(new UserVerificationTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new UserPresenceVerificationTest(this.api, WebAuthnTestType.REGISTRATION));
        registrationTests.add(new CredentialPublicKeyTest(this.api, WebAuthnTestType.REGISTRATION));

//        The following 4 are useless tests
//        registrationTests.add(new UserBackupBEBSTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataOriginPathTest(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataOriginPathTest2(this.api, WebAuthnTestType.REGISTRATION));
//        registrationTests.add(new ClientDataCrossOriginTest(this.api, WebAuthnTestType.REGISTRATION));

//        AUTHENTICATION TESTS
        authenticationTests.add(new NaiveTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new CredentialIdTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataCreateTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataChallengeTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataOriginTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataOriginSubdomainTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new AuthenticatorDataTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new UserPresenceTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new UserVerificationTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new UserPresenceVerificationTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new SignatureTest(this.api, WebAuthnTestType.AUTHENTICATION));
        authenticationTests.add(new SignCountTest(this.api, WebAuthnTestType.AUTHENTICATION));
        authenticationTests.add(new SignCountGreaterTest(this.api, WebAuthnTestType.AUTHENTICATION));

//        The following 4 are useless tests
//        authenticationTests.add(new UserBackupBEBSTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataOriginPathTest(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataOriginPathTest2(this.api, WebAuthnTestType.AUTHENTICATION));
//        authenticationTests.add(new ClientDataCrossOriginTest(this.api, WebAuthnTestType.AUTHENTICATION));
    }

    public ArrayList<WebAuthnTest> getRegistrationTests() {
        return registrationTests;
    }

    public ArrayList<WebAuthnTest> getAuthenticationTests() {
        return authenticationTests;
    }

}
