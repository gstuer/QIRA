package com.gstuer.qira.core.cryptography.signcryption.algorithm;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signcryption.Signcrypter;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class AES256GCM extends Signcrypter<SecretKey, SecretKey> {
    public static final String ALGORITHM_IDENTIFIER = "AES/GCM/NoPadding";
    public static final int KEY_LENGTH = 256;
    public static final int TAG_LENGTH = 128;
    public static final int INITIALIZATION_VECTOR_BYTE = 16;

    @Override
    public void initializeKeyPair() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_LENGTH, SecureRandom.getInstanceStrong());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        SecretKey key = keyGenerator.generateKey();
        this.setEncryptionKey(key);
        this.setDecryptionKey(key);
    }

    @Override
    public byte[] decrypt(byte[] data) throws InvalidKeyException, SignatureException {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTE];
        buffer.get(initializationVector);

        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, initializationVector);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ALGORITHM_IDENTIFIER);
            cipher.init(Cipher.DECRYPT_MODE, this.getDecryptionKey(), gcmParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }

        try {
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException exception) {
            // Thrown if cipher is unable to verify the supplied authentication tag.
            throw new SignatureException(exception);
        } catch (IllegalBlockSizeException | BadPaddingException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
    }

    @Override
    public void setDecryptionKey(EncodedKey encodedKey) {
        if (!encodedKey.getAlgorithmIdentifier().equals(this.getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Incompatible algorithm identifier of encoded key.");
        }
        SecretKeySpec keySpec = new SecretKeySpec(encodedKey.getKey(), this.getAlgorithmIdentifier());
        this.setDecryptionKey(keySpec);
    }

    @Override
    public byte[] encrypt(byte[] data) throws InvalidKeyException {
        SecureRandom random;
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ALGORITHM_IDENTIFIER);
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTE];
        random.nextBytes(initializationVector);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, initializationVector);


        byte[] ciphertext;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.getEncryptionKey(), gcmParameterSpec);
            ciphertext = cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }

        return ByteBuffer.allocate(initializationVector.length + ciphertext.length)
                .put(initializationVector)
                .put(ciphertext)
                .array();
    }

    @Override
    public void setEncryptionKey(EncodedKey encodedKey) throws InvalidKeySpecException {
        if (!encodedKey.getAlgorithmIdentifier().equals(this.getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Incompatible algorithm identifier of encoded key.");
        }
        SecretKeySpec keySpec = new SecretKeySpec(encodedKey.getKey(), this.getAlgorithmIdentifier());
        this.setEncryptionKey(keySpec);
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }
}
