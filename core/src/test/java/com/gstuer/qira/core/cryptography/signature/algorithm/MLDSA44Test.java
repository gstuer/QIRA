package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.signature.AuthenticatorTest;

public class MLDSA44Test extends AuthenticatorTest<MLDSA44> {
    @Override
    protected MLDSA44 constructAuthenticator() {
        return new MLDSA44();
    }
}
