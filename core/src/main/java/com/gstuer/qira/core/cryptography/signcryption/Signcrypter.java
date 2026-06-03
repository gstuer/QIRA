package com.gstuer.qira.core.cryptography.signcryption;

import com.gstuer.qira.core.encapsulation.EncapsulationException;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.message.EncryptedMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.Serial;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Security;
import java.security.SignatureException;
import java.util.Objects;

public abstract class Signcrypter<S extends Key, V extends Key> extends KeyedMessageEncapsulator<S, V> implements Encrypter<S>, Decrypter<V> {
    @Serial
    private static final long serialVersionUID = -3692956892196228521L;

    protected Signcrypter() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public abstract void initializeKeyPair();

    @Override
    public V getDecryptionKey() {
        return this.getDecapsulationKey();
    }

    @Override
    public void setDecryptionKey(V key) {
        this.setDecapsulationKey(Objects.requireNonNull(key));
    }

    @Override
    public S getEncryptionKey() {
        return this.getEncapsulationKey();
    }

    @Override
    public void setEncryptionKey(S key) {
        this.setEncapsulationKey(Objects.requireNonNull(key));
    }

    @Override
    public Message<?> encapsulate(Message<?> message) throws EncapsulationException {
        try {
            return message.encrypt(this);
        } catch (InvalidKeyException exception) {
            throw new EncapsulationException("Signcryption failed: " + exception);
        }
    }

    @Override
    public Message<?> decapsulate(Message<?> message) throws EncapsulationException {
        if (message instanceof EncryptedMessage encryptedMessage) {
            try {
                return encryptedMessage.decrypt(this);
            } catch (SerializationException | SignatureException | InvalidKeyException exception) {
                throw new EncapsulationException("Unsigncryption failed: " + exception);
            }
        } else {
            throw new EncapsulationException("Incompatible encapsulation.");
        }
    }
}
