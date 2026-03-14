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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class ChaCha20Poly1305 extends Signcrypter<SecretKey, SecretKey> {
    public static final String ALGORITHM_IDENTIFIER = "ChaCha20-Poly1305/None/NoPadding";
    public static final int KEY_LENGTH = 256;
    public static final int NONCE_BYTE = 12;

    @Override
    public void initializeKeyPair() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("ChaCha20");
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
        byte[] nonce = new byte[NONCE_BYTE];
        buffer.get(nonce);

        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ALGORITHM_IDENTIFIER);
            cipher.init(Cipher.DECRYPT_MODE, this.getDecryptionKey(), ivParameterSpec);
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
        byte[] nonce = new byte[NONCE_BYTE];
        random.nextBytes(nonce);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);


        byte[] ciphertext;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.getEncryptionKey(), ivParameterSpec);
            ciphertext = cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }

        return ByteBuffer.allocate(nonce.length + ciphertext.length)
                .put(nonce)
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
