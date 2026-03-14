package com.gstuer.qira.message;

import com.gstuer.qira.core.cryptography.signcryption.Signcrypter;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256GCM;
import com.gstuer.qira.core.message.EncryptedMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptedMessageTest extends MessageTest<EncryptedMessage> {
    public Signcrypter<?, ?> constructSigncrypter() {
        Signcrypter<?, ?> signcrypter = new AES256GCM();
        signcrypter.initializeKeyPair();
        return signcrypter;
    }

    @Test
    public void testEncryptAndDecrypt() throws Throwable {
        Signcrypter<?, ?> signcrypter = this.constructSigncrypter();
        Message<?> encapsulatedMessage = this.constructEncapsulatedMessage();

        // Encrypt message
        EncryptedMessage encryptedMessage = encapsulatedMessage.encrypt(signcrypter);
        assertNotNull(encryptedMessage.getPayload());
        assertEquals(signcrypter.getAlgorithmIdentifier(), encryptedMessage.getEncrypterIdentifier());

        // Decrypt message
        PayloadExchangeMessage decryptedMessage = (PayloadExchangeMessage) encryptedMessage.decrypt(signcrypter);
        assertEquals(encapsulatedMessage, decryptedMessage);
    }

    @Test
    public void testDoubleEncryptAndDecrypt() throws Throwable {
        Signcrypter<?, ?> innerSigncrypter = this.constructSigncrypter();
        Signcrypter<?, ?> outerSigncrypter = this.constructSigncrypter();
        Message<?> encapsulatedMessage = this.constructEncapsulatedMessage();

        // Encrypt encapsulated message
        EncryptedMessage encryptedMessage = encapsulatedMessage.encrypt(innerSigncrypter);
        EncryptedMessage encryptedEncryptedMessage = encryptedMessage.encrypt(outerSigncrypter);

        // Check that inner and outer encrypter are different
        assertThrows(SignatureException.class, () -> encryptedEncryptedMessage.decrypt(innerSigncrypter));

        // Decrypt outer message
        EncryptedMessage decryptedMessage = (EncryptedMessage) encryptedEncryptedMessage.decrypt(outerSigncrypter);
        assertEquals(encryptedMessage, decryptedMessage);

        // Decrypt inner message
        PayloadExchangeMessage decryptedDecryptedMessage = (PayloadExchangeMessage) decryptedMessage.decrypt(innerSigncrypter);
        assertEquals(encapsulatedMessage, decryptedDecryptedMessage);
    }

    @Override
    protected EncryptedMessage constructMessage() throws Throwable {
        return this.constructEncapsulatedMessage().encrypt(this.constructSigncrypter());
    }

    protected Message<?> constructEncapsulatedMessage() throws Throwable {
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Packet packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();
        return new PayloadExchangeMessage(source, destination, packet);
    }
}
