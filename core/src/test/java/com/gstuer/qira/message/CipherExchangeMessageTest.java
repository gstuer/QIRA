package com.gstuer.qira.message;

import com.gstuer.qira.core.cryptography.signcryption.Signcrypter;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256GCM;
import com.gstuer.qira.core.message.CipherExchangeMessage;

import java.net.InetAddress;

public class CipherExchangeMessageTest extends MessageTest<CipherExchangeMessage> {
    @Override
    protected CipherExchangeMessage constructMessage() throws Throwable {
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Signcrypter<?, ?> cipher = new AES256GCM();
        cipher.initializeKeyPair();
        return new CipherExchangeMessage(source, destination, cipher);
    }
}
