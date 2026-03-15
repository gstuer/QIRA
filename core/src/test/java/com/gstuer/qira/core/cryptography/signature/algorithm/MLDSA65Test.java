package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.signature.AuthenticatorTest;

public class MLDSA65Test extends AuthenticatorTest<MLDSA65> {
    @Override
    protected MLDSA65 constructAuthenticator() {
        return new MLDSA65();
    }
}
