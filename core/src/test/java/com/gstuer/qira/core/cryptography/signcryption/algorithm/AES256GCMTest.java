package com.gstuer.qira.core.cryptography.signcryption.algorithm;

import com.gstuer.qira.core.cryptography.signcryption.SigncrypterTest;

public class AES256GCMTest extends SigncrypterTest<AES256GCM> {
    @Override
    protected AES256GCM constructSigncrypter() {
        return new AES256GCM();
    }
}