package com.gstuer.qira.core.message;

import com.gstuer.qira.core.cryptography.signcryption.Decrypter;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class EncryptedMessage extends Message<byte[]> {
    @Serial
    private static final long serialVersionUID = 4039446179111666190L;
    private final String encrypterIdentifier;

    protected EncryptedMessage(InetAddress source, InetAddress destination, byte[] payload, String encrypterIdentifier) {
        super(source, destination, payload);
        this.encrypterIdentifier = encrypterIdentifier;
    }

    protected EncryptedMessage(InetAddress destination, byte[] payload, String algorithmIdentifier) {
        super(destination, payload);
        this.encrypterIdentifier = algorithmIdentifier;
    }

    public Message<?> decrypt(Decrypter<?> decrypter) throws SignatureException, InvalidKeyException, SerializationException {
        return new JsonProcessor().deserialize(decrypter.decrypt(this.getPayload()), Message.class);
    }

    @Override
    public Message<byte[]> fromSource(InetAddress source) {
        return new EncryptedMessage(source, this.getDestination(), this.getPayload(), this.getEncrypterIdentifier());
    }

    public String getEncrypterIdentifier() {
        return encrypterIdentifier;
    }
}
