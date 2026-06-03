package com.gstuer.qira.core.cryptography.signature;

import com.gstuer.qira.core.encapsulation.EncapsulationException;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.Message;

import java.io.Serial;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.util.Objects;

public abstract class Authenticator<S extends Key, V extends Key> extends KeyedMessageEncapsulator<S, V> implements Signer<S>, Verifier<V> {
    @Serial
    private static final long serialVersionUID = -6368161093200916637L;

    @Override
    public V getVerificationKey() {
        return this.getDecapsulationKey();
    }

    @Override
    public void setVerificationKey(V verificationKey) {
        this.setDecapsulationKey(Objects.requireNonNull(verificationKey));
    }

    public abstract void initializeKeyPair();

    public abstract Verifier<V> getShareableVerifier();

    @Override
    public Message<?> decapsulate(Message<?> message) throws EncapsulationException {
        if (message instanceof AuthenticatedMessage authenticatedMessage) {
            if (authenticatedMessage.verify(this)) {
                return authenticatedMessage.getPayload();
            } else {
                throw new EncapsulationException("Verification failed.");
            }
        } else {
            throw new EncapsulationException("Incompatible encapsulation.");
        }
    }

    @Override
    public AuthenticatedMessage encapsulate(Message<?> message) throws EncapsulationException {
        try {
            return message.sign(this);
        } catch (SignatureException | InvalidKeyException exception) {
            throw new EncapsulationException("Signing failed: " + exception);
        }
    }

    protected S getSigningKey() {
        return this.getEncapsulationKey();
    }

    @Override
    public void setSigningKey(S signingKey) {
        this.setEncapsulationKey(Objects.requireNonNull(signingKey));
    }
}
