package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.signature.AuthenticatorTest;

public class HmacSHA256Test extends AuthenticatorTest<HmacSHA256> {
    @Override
    protected HmacSHA256 constructAuthenticator() {
        return new HmacSHA256();
    }
}
