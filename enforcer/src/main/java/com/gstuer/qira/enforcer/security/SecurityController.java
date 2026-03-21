package com.gstuer.qira.enforcer.security;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA65;
import com.gstuer.qira.core.cryptography.signcryption.Signcrypter;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256GCM;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.EncryptedMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import com.gstuer.qira.core.serialization.SerializationException;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public class SecurityController {
    private final BlockingQueue<Message<?>> messageEgress;
    private final BlockingQueue<Packet> packetEgress;
    private final Authenticator<?, ?> authenticator;
    private final Signcrypter<?, ?> signcrypter;

    public SecurityController(BlockingQueue<Message<?>> messageEgress, BlockingQueue<Packet> packetEgress) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.packetEgress = Objects.requireNonNull(packetEgress);

        // TODO Replace with key establishment
//        this.authenticator = new AES256GMAC();
        this.signcrypter = new AES256GCM();
//        try {
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            KeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 65536, 256);
//            SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
//
//            this.authenticator.setSigningKey(new EncodedKey(this.authenticator.getAlgorithmIdentifier(), secretKey.getEncoded()));
//            this.authenticator.setVerificationKey(new EncodedKey(this.authenticator.getAlgorithmIdentifier(), secretKey.getEncoded()));
//            this.signcrypter.setEncryptionKey(new EncodedKey(this.signcrypter.getAlgorithmIdentifier(), secretKey.getEncoded()));
//            this.signcrypter.setDecryptionKey(new EncodedKey(this.signcrypter.getAlgorithmIdentifier(), secretKey.getEncoded()));
//        } catch (Exception exception) {
//            throw new RuntimeException(exception);
//        }

        this.authenticator = new MLDSA65();
        byte[] seed = "static_password_seed".getBytes(StandardCharsets.UTF_8);
        SecureRandom deterministicRandom;
        KeyPairGenerator keyPairGenerator;
        try {
            deterministicRandom = SecureRandom.getInstance("SHA1PRNG");
            deterministicRandom.setSeed(seed);
            keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA");
            keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_65, deterministicRandom);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            this.authenticator.setSigningKey(new EncodedKey(this.authenticator.getAlgorithmIdentifier(), keyPair.getPrivate().getEncoded()));
            this.authenticator.setVerificationKey(new EncodedKey(this.authenticator.getAlgorithmIdentifier(), keyPair.getPublic().getEncoded()));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException exception) {
            throw new RuntimeException(exception);
        }
    }

    public void handleOutgoingRequest(Packet packet) {
        PayloadExchangeMessage message;
        try {
            if (((EthernetPacket.EthernetHeader) packet.getHeader()).getSrcAddr().equals(MacAddress.getByName("2c:cf:67:a8:51:24"))) {
                message = new PayloadExchangeMessage(InetAddress.getByName("192.168.0.61"), packet);
            } else if (((EthernetPacket.EthernetHeader) packet.getHeader()).getSrcAddr().equals(MacAddress.getByName("2c:cf:67:a8:51:7e"))) {
                message = new PayloadExchangeMessage(InetAddress.getByName("192.168.0.60"), packet);
            } else {
                // TODO Handle unknown sender
                System.out.println("Unknown sender of frame.");
                return;
            }
        } catch (UnknownHostException exception) {
            throw new RuntimeException(exception);
        }

        // TODO Replace with address and algorithm lookup
        try {
            this.messageEgress.offer(message.sign(this.authenticator));
//            this.messageEgress.offer(message.encrypt(this.signcrypter));
        } catch (InvalidKeyException | SignatureException exception) {
            throw new RuntimeException(exception);
        }
    }

    public void handleIncomingRequest(Message<?> incomingMessage) {
        // TODO Replace with message handling based on sender of message
        if (incomingMessage instanceof PayloadExchangeMessage message) {
            this.packetEgress.offer(message.getPayload());
        } else if (incomingMessage instanceof AuthenticatedMessage message) {
            if (message.verify(this.authenticator)) {
                this.handleIncomingRequest(message.getPayload());
            }
        } else if (incomingMessage instanceof EncryptedMessage message) {
            try {
                this.handleIncomingRequest(message.decrypt(this.signcrypter));
            } catch (SignatureException | InvalidKeyException | SerializationException exception) {
                throw new RuntimeException(exception);
            }
        } else {
            System.out.println("[AC] Unknown message type.");
        }
    }
}
