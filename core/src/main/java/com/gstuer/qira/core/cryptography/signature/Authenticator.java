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

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        Authenticator<?, ?> that = (Authenticator<?, ?>) object;
        return Objects.equals(this.signingKey, that.signingKey) && Objects.equals(this.verificationKey, that.verificationKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.signingKey, this.verificationKey);
    }

    protected S getSigningKey() {
        return this.signingKey;
    }

    @Override
    public void setSigningKey(S signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }
}
