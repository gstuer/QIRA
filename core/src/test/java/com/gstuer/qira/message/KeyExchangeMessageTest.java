package com.gstuer.qira.message;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signcryption.Signcrypter;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256GCM;
import com.gstuer.qira.core.message.KeyExchangeMessage;

import java.net.InetAddress;

public class KeyExchangeMessageTest extends MessageTest<KeyExchangeMessage> {
    @Override
    protected KeyExchangeMessage constructMessage() throws Throwable {
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Signcrypter<?, ?> cipher = new AES256GCM();
        cipher.initializeKeyPair();
        return new KeyExchangeMessage(source, destination,
                new EncodedKey(cipher.getAlgorithmIdentifier(), cipher.getDecryptionKey().getEncoded()));
    }
}
