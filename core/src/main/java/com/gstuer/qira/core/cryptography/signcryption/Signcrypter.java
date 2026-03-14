package com.gstuer.qira.core.cryptography.signcryption;

import java.security.Key;
import java.security.Security;
import java.util.Objects;

public abstract class Signcrypter<S extends Key, V extends Key> implements Encrypter<S>, Decrypter<V> {
    private S encryptionKey;
    private V decryptionKey;

    protected Signcrypter() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public abstract void initializeKeyPair();

    @Override
    public V getDecryptionKey() {
        return this.decryptionKey;
    }

    @Override
    public void setDecryptionKey(V key) {
        this.decryptionKey = Objects.requireNonNull(key);
    }

    @Override
    public S getEncryptionKey() {
        return this.encryptionKey;
    }

    @Override
    public void setEncryptionKey(S key) {
        this.encryptionKey = Objects.requireNonNull(key);
    }
}
