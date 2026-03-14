package com.gstuer.qira.core.cryptography.signcryption;

import com.gstuer.qira.core.cryptography.signature.Signer;

/**
 * Represents an objects that can be encrypted using an arbitrary {@link Encrypter encrypter} instance.
 */
public interface Encryptable {
    /**
     * Converts this object into its byte representation, i.e. the method must return distinct
     * byte representations for objects that are distinct with regard to {@link Object#equals(Object)}.
     *
     * @return the byte representation of this object.
     */
    public byte[] getEncryptionData();
}
