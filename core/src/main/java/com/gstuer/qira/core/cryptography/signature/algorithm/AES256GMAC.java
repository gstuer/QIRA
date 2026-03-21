package com.gstuer.qira.core.cryptography.signature.algorithm;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.DigitalSignature;
import com.gstuer.qira.core.cryptography.signature.Verifier;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serial;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES256GMAC extends Authenticator<SecretKey, SecretKey> {
    public static final String ALGORITHM_IDENTIFIER = "AES256GMAC";
    public static final int KEY_LENGTH = 256;
    public static final int TAG_LENGTH = 128;
    public static final int INITIALIZATION_VECTOR_BYTE = 16;
    @Serial
    private static final long serialVersionUID = 1932665552233124268L;

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
        this.setSigningKey(key);
        this.setVerificationKey(key);
    }

    @Override
    public Verifier<SecretKey> getShareableVerifier() {
        // Create new verifier from authenticator omitting the signing key
        Verifier<SecretKey> verifier = new AES256GMAC();
        verifier.setVerificationKey(this.getVerificationKey());
        return verifier;
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) {
        ByteBuffer buffer = ByteBuffer.wrap(signature.getData());
        byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTE];
        buffer.get(initializationVector);
        byte[] signatureTag = new byte[TAG_LENGTH];
        buffer.get(signatureTag);

        // Initialize GMAC
        GMac gmac = new GMac(GCMBlockCipher.newInstance(AESEngine.newInstance()), TAG_LENGTH);
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(this.getSigningKey().getEncoded()), initializationVector);
        gmac.init(params);

        // Verify Signature
        gmac.update(data, 0, data.length);
        byte[] verifyTag = new byte[TAG_LENGTH];
        gmac.doFinal(verifyTag, 0);
        return Arrays.equals(signatureTag, verifyTag);
    }

    @Override
    public void setVerificationKey(EncodedKey encodedKey) {
        if (!encodedKey.getAlgorithmIdentifier().equals(this.getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Incompatible algorithm identifier of encoded key.");
        }
        SecretKeySpec keySpec = new SecretKeySpec(encodedKey.getKey(), this.getAlgorithmIdentifier());
        this.setVerificationKey(keySpec);
    }

    public DigitalSignature sign(byte[] data) {
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException exception) {
            // Thrown in case of a non-available secure random at platform
            throw new UnsupportedOperationException(exception);
        }
        byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTE];
        random.nextBytes(initializationVector);

        // Initialize GMAC
        GMac gmac = new GMac(GCMBlockCipher.newInstance(AESEngine.newInstance()), TAG_LENGTH);
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(this.getSigningKey().getEncoded()), initializationVector);
        gmac.init(params);

        // Generate Tag
        gmac.update(data, 0, data.length);
        byte[] tag = new byte[TAG_LENGTH];
        gmac.doFinal(tag, 0);

        // Prepend init vector to tag for serialization
        byte[] signatureWithInitVector = ByteBuffer.allocate(INITIALIZATION_VECTOR_BYTE + TAG_LENGTH)
                .put(initializationVector)
                .put(tag)
                .array();
        return new DigitalSignature(signatureWithInitVector, this.getAlgorithmIdentifier());
    }

    @Override
    public void setSigningKey(EncodedKey encodedKey) {
        if (!encodedKey.getAlgorithmIdentifier().equals(this.getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Incompatible algorithm identifier of encoded key.");
        }
        SecretKeySpec keySpec = new SecretKeySpec(encodedKey.getKey(), this.getAlgorithmIdentifier());
        this.setSigningKey(keySpec);
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }
}
