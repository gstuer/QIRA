package com.gstuer.qira.core.cryptography.signcryption.algorithm;

import com.gstuer.qira.core.cryptography.signcryption.SigncrypterTest;

public class ChaCha20Poly1305Test extends SigncrypterTest<ChaCha20Poly1305> {
    @Override
    protected ChaCha20Poly1305 constructSigncrypter() {
        return new ChaCha20Poly1305();
    }
}
