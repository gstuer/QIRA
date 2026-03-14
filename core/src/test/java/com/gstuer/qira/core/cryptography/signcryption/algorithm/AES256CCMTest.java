package com.gstuer.qira.core.cryptography.signcryption.algorithm;

import com.gstuer.qira.core.cryptography.signcryption.SigncrypterTest;

public class AES256CCMTest extends SigncrypterTest<AES256CCM> {
    @Override
    protected AES256CCM constructSigncrypter() {
        return new AES256CCM();
    }
}
