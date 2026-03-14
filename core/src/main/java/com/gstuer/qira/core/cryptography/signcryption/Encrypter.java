package com.gstuer.qira.core.cryptography.signcryption;

import com.gstuer.qira.core.cryptography.EncodedKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.InvalidKeySpecException;

public interface Encrypter<T extends Key> {
    public byte[] encrypt(byte[] data) throws InvalidKeyException;

    public default byte[] encrypt(Encryptable data) throws InvalidKeyException {
        return encrypt(data.getEncryptionData());
    }

    public T getEncryptionKey();

    public void setEncryptionKey(T key);

    public void setEncryptionKey(EncodedKey encodedKey) throws InvalidKeySpecException;

    public String getAlgorithmIdentifier();
}
