package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.signature.AuthenticatorTest;

public class AES256GMACTest extends AuthenticatorTest<AES256GMAC> {
    @Override
    protected AES256GMAC constructAuthenticator() {
        return new AES256GMAC();
    }
}