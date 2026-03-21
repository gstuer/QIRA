package com.gstuer.qira.core.cryptography.signature;

import com.gstuer.qira.core.serialization.JsonProcessor;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Duration;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public abstract class AuthenticatorTest<T extends Authenticator<?, ?>> {
    private final T authenticator;

    protected AuthenticatorTest() {
        this.authenticator = constructAuthenticator();
        this.authenticator.initializeKeyPair();
    }

    public T getAuthenticator() {
        return authenticator;
    }

    @Test
    public void testTagAndVerifyWithSameAuthenticator() throws SignatureException, InvalidKeyException {
        byte[] data = new byte[1500];
        new Random().nextBytes(data);
        Authenticator<?, ?> authenticator = this.getAuthenticator();

        // Warm-up of JVM
        for (int i = 0; i < 1000; i++)
            authenticator.verify(data, authenticator.sign(data));

        // Create digital signature
        long nanosBeforeSign = System.nanoTime();
        DigitalSignature signature = authenticator.sign(data);
        Duration signDuration = Duration.ofNanos(System.nanoTime() - nanosBeforeSign);
        assertTrue(signature.getData().length > 0);
        assertEquals(authenticator.getAlgorithmIdentifier(), signature.getAlgorithmIdentifier());

        // Verify digital signature
        long nanosBeforeVerify = System.nanoTime();
        assertTrue(authenticator.verify(data, signature));
        Duration verifyDuration = Duration.ofNanos(System.nanoTime() - nanosBeforeVerify);

        // Output algorithm information
        System.out.println("[TEST " + this.getAuthenticator().getClass().getCanonicalName() + "]");
        System.out.println("Data Byte: " + data.length);
        System.out.println("Signature Byte: " + signature.getData().length);
        System.out.println("Sign Duration (ms): " + signDuration.toNanos() / Math.pow(10, 6));
        System.out.println("Verify Duration (ms): " + verifyDuration.toNanos() / Math.pow(10, 6));
    }

    @Test
    public void testShareableVerifierIsSecureAndSerializable() throws Throwable {
        Authenticator<?, ?> authenticator = this.getAuthenticator();
        Verifier<?> verifier = authenticator.getShareableVerifier();

        // Check that verifier is correct and does not contain singing key material
        assertEquals(authenticator.getClass(), verifier.getClass()); // Same auth. class
        assertEquals(authenticator.getVerificationKey(), verifier.getVerificationKey()); // Same verif. key
        assertNotNull(authenticator.getSigningKey()); // Auth. had signing key
        assertNull(((Authenticator<?, ?>) verifier).getSigningKey()); // Verify has no signing key

        // Check that verifier is serializable and deserializable
        JsonProcessor jsonProcessor = new JsonProcessor();
        Verifier<?> deserialVerifier = (Authenticator<?, ?>) jsonProcessor.deserialize(jsonProcessor.serialize(verifier), Authenticator.class);
        assertEquals(verifier.getClass(), deserialVerifier.getClass());
        assertEquals(verifier.getAlgorithmIdentifier(), deserialVerifier.getAlgorithmIdentifier());
        assertEquals(verifier.getVerificationKey(), deserialVerifier.getVerificationKey());
    }

    protected abstract T constructAuthenticator();
}
