package com.gstuer.qira.core.cryptography.signcryption;

import com.gstuer.qira.core.serialization.JsonProcessor;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Duration;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public abstract class SigncrypterTest<T extends Signcrypter<?, ?>> {
    private final T signcrypter;

    protected SigncrypterTest() {
        this.signcrypter = constructSigncrypter();
    }

    public T getSigncrypter() {
        return this.signcrypter;
    }

    @Test
    public void testEncryptionDecryptionWithRandomMessage() throws InvalidKeyException, SignatureException {
        Signcrypter<?, ?> signcrypter = this.signcrypter;
        signcrypter.initializeKeyPair();
        byte[] originalData = new byte[1500];
        new Random().nextBytes(originalData);

        // Warm-up of JVM
        for (int i = 0; i < 1000; i++)
            signcrypter.decrypt(signcrypter.encrypt(originalData));

        // Encrypt data
        long nanosBeforeSigncrypt = System.nanoTime();
        byte[] encryptedData = signcrypter.encrypt(originalData);
        Duration signcryptDuration = Duration.ofNanos(System.nanoTime() - nanosBeforeSigncrypt);
        assertNotEquals(originalData, encryptedData);
        assertTrue(encryptedData.length > originalData.length);

        // Decrypt data
        long nanosBeforeUnsigncrypt = System.nanoTime();
        byte[] decryptedData = signcrypter.decrypt(encryptedData);
        Duration unsigncryptDuration = Duration.ofNanos(System.nanoTime() - nanosBeforeUnsigncrypt);
        assertArrayEquals(originalData, decryptedData);
        assertEquals(decryptedData.length, originalData.length);

        // Output algorithm information
        System.out.println("[TEST " + this.getSigncrypter().getClass().getCanonicalName() + "]");
        System.out.println("Data Byte: " + originalData.length);
        System.out.println("Ciphertext Byte: " + encryptedData.length);
        System.out.println("Signcrypt Duration (ms): " + signcryptDuration.toNanos() / Math.pow(10, 6));
        System.out.println("Unsigncrypt Duration (ms): " + unsigncryptDuration.toNanos() / Math.pow(10, 6));
    }

    @Test
    public void testCipherSerializable() throws Throwable {
        Signcrypter<?, ?> signcrypter = this.getSigncrypter();

        // Check that cipher is correct and does not contain key material
        assertNull(signcrypter.getEncryptionKey());
        assertNull(signcrypter.getDecryptionKey());

        // Check that verifier is serializable and deserializable
        JsonProcessor jsonProcessor = new JsonProcessor();
        Signcrypter<?, ?> deserialSigncrypter = jsonProcessor.deserialize(jsonProcessor.serialize(signcrypter), Signcrypter.class);
        assertEquals(signcrypter.getClass(), deserialSigncrypter.getClass());
        assertEquals(signcrypter.getAlgorithmIdentifier(), deserialSigncrypter.getAlgorithmIdentifier());
        assertNull(deserialSigncrypter.getEncryptionKey());
        assertNull(deserialSigncrypter.getDecryptionKey());
    }

    protected abstract T constructSigncrypter();
}
