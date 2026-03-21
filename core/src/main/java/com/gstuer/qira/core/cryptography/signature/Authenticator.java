package com.gstuer.qira.core.cryptography.signature;

import java.io.Serial;
import java.io.Serializable;
import java.security.Key;
import java.util.Objects;

public abstract class Authenticator<S extends Key, V extends Key> implements Signer<S>, Verifier<V>, Serializable {
    @Serial
    private static final long serialVersionUID = -6368161093200916637L;

    private S signingKey;
    private V verificationKey;

    @Override
    public V getVerificationKey() {
        return this.verificationKey;
    }

    @Override
    public void setVerificationKey(V verificationKey) {
        this.verificationKey = Objects.requireNonNull(verificationKey);
    }

    public abstract void initializeKeyPair();

    public abstract Verifier<V> getShareableVerifier();

    protected S getSigningKey() {
        return this.signingKey;
    }

    @Override
    public void setSigningKey(S signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }
}
