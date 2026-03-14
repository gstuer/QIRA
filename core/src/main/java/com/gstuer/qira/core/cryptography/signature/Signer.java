package com.gstuer.qira.core.cryptography.signature;

import com.gstuer.qira.core.cryptography.EncodedKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface Signer<T extends Key> {
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException;

    public default DigitalSignature sign(Signable data) throws InvalidKeyException, SignatureException {
        return sign(data.getSigningData());
    }

    public void setSigningKey(T signingKey);

    public void setSigningKey(EncodedKey encodedSigningKey) throws InvalidKeySpecException;

    public String getAlgorithmIdentifier();
}
