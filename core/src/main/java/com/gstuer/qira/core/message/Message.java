package com.gstuer.qira.core.message;

import com.gstuer.qira.core.cryptography.signature.DigitalSignature;
import com.gstuer.qira.core.cryptography.signature.Signable;
import com.gstuer.qira.core.cryptography.signature.Signer;
import com.gstuer.qira.core.cryptography.signcryption.Encryptable;
import com.gstuer.qira.core.cryptography.signcryption.Encrypter;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;

public abstract class Message<T> implements Serializable, Signable, Encryptable {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    private final String sourceAddress;
    private final String destinationAddress;
    private final T payload;

    protected Message(InetAddress source, InetAddress destination, T payload) {
        this.sourceAddress = Objects.isNull(source) ? null : source.getHostAddress();
        this.destinationAddress = destination.getHostAddress();
        this.payload = payload;
    }

    protected Message(InetAddress destination, T payload) {
        this(null, destination, payload);
    }

    public InetAddress getSource() {
        if (Objects.isNull(this.sourceAddress)) {
            return null;
        }
        try {
            return InetAddress.getByName(this.sourceAddress);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public InetAddress getDestination() {
        try {
            return InetAddress.getByName(this.destinationAddress);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public T getPayload() {
        return this.payload;
    }

    public boolean hasPayload() {
        return Objects.nonNull(this.getPayload());
    }

    public abstract Message<T> fromSource(InetAddress source);

    @Override
    public String toString() {
        try {
            String json = new JsonProcessor(true).convertToJson(this);
            return "[" + this.getClass().getSimpleName() + "]" + json;
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        Message<?> that = (Message<?>) object;
        return Objects.equals(this.sourceAddress, that.sourceAddress)
                && Objects.equals(this.destinationAddress, that.destinationAddress)
                && this.hasEqualPayload(that);
    }

    public AuthenticatedMessage sign(Signer<?> signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(this.getSigningData());
        return new AuthenticatedMessage(this.getSource(), this.getDestination(), this, signature);
    }

    public EncryptedMessage encrypt(Encrypter<?> encrypter) throws InvalidKeyException {
        return new EncryptedMessage(this.getSource(), this.getDestination(),
                encrypter.encrypt(this.getEncryptionData()), encrypter.getAlgorithmIdentifier());
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceAddress, destinationAddress, payload);
    }

    @Override
    public byte[] getSigningData() {
        String json;
        try {
            json = new JsonProcessor(false).convertToJson(this);

        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
        return json.getBytes(JsonProcessor.getDefaultCharset());
    }

    @Override
    public byte[] getEncryptionData() {
        String json;
        try {
            json = new JsonProcessor(false).convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
        return json.getBytes(JsonProcessor.getDefaultCharset());
    }

    /**
     * Checks if destination of message equals destination of nested, i.e. encapsulated messages.
     * May only be false for messages carrying other messages as payload.
     *
     * @return True if destination equals destination of payload, or if payload is no message. False otherwise.
     */
    public boolean hasConsistentDestination() {
        return true;
    }

    /**
     * Checks if destination of message equals destination of nested, i.e. encapsulated messages.
     * Moreover, checks if destination equals external destination provided via parameter.
     *
     * @param externalDestination Related destination not contained within message object, e.g, TCP/UDP destination address of socket.
     * @return True if destination is consistent and equals external destination. False otherwise.
     */
    public boolean hasConsistentDestination(InetAddress externalDestination) {
        return this.getDestination().equals(externalDestination) && this.hasConsistentDestination();
    }

    /**
     * Checks if source of message equals source of nested, i.e. encapsulated messages.
     * May only be false for messages carrying other messages as payload.
     *
     * @return True if source equals source of payload, or if payload is no message. False otherwise.
     */
    public boolean hasConsistentSource() {
        return true;
    }

    /**
     * Checks if source of message equals source of nested, i.e. encapsulated messages.
     * Moreover, checks if source equals external source provided via parameter.
     *
     * @param externalSource Related source not contained within message object, e.g, TCP/UDP sender address of socket.
     * @return True if source is consistent and equals external source. False otherwise.
     */
    public boolean hasConsistentSource(InetAddress externalSource) {
        return this.getSource().equals(externalSource) && this.hasConsistentSource();
    }

    protected boolean hasEqualPayload(Message<?> message) {
        return Objects.deepEquals(this.payload, message.getPayload());
    }
}
