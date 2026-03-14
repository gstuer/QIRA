package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.signature.AuthenticatorTest;

public class MLDSA87Test extends AuthenticatorTest<MLDSA87> {
    @Override
    protected MLDSA87 constructAuthenticator() {
        return new MLDSA87();
    }
}
