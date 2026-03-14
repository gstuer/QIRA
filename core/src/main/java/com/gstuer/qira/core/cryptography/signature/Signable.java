package com.gstuer.qira.core.cryptography.signature;

/**
 * Represents an objects that can be signed using an arbitrary {@link Signer signer} instance.
 */
public interface Signable {
    /**
     * Converts this object into its byte representation, i.e. the method must return distinct
     * byte representations for objects that are distinct with regard to {@link Object#equals(Object)}.
     *
     * @return the byte representation of this object.
     */
    public byte[] getSigningData();
}
