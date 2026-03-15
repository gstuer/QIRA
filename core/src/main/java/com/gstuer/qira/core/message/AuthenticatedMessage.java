package com.gstuer.qira.core.message;

import com.gstuer.qira.core.cryptography.signature.DigitalSignature;
import com.gstuer.qira.core.cryptography.signature.Verifier;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;

public class AuthenticatedMessage extends Message<Message<?>> {
    private final DigitalSignature signature;

    protected AuthenticatedMessage(InetAddress source, InetAddress destination, Message<?> payload, DigitalSignature signature) {
        super(source, destination, payload);
        this.signature = Objects.requireNonNull(signature);
    }

    protected AuthenticatedMessage(InetAddress destination, Message<?> payload, DigitalSignature signature) {
        super(destination, payload);
        this.signature = Objects.requireNonNull(signature);
    }

    public boolean verify(Verifier<?> verifier) throws SignatureException, InvalidKeyException {
        return verifier.verify(this.getPayload().getSigningData(), this.signature);
    }

    public DigitalSignature getSignature() {
        return this.signature;
    }

    @Override
    public Message<Message<?>> fromSource(InetAddress source) {
        return new AuthenticatedMessage(Objects.requireNonNull(source), this.getDestination(), this.getPayload(), this.getSignature());
    }
}
