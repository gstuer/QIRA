package com.gstuer.qira.core.cryptography.signcryption;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signature.DigitalSignature;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface Decrypter<T extends Key> {
    public byte[] decrypt(byte[] data) throws InvalidKeyException, SignatureException;

    public T getDecryptionKey();

    public void setDecryptionKey(T key);

    public void setDecryptionKey(EncodedKey encodedKey) throws InvalidKeySpecException;

    public String getAlgorithmIdentifier();
}
