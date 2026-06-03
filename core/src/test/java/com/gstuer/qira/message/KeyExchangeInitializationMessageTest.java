package com.gstuer.qira.message;

import com.gstuer.qira.core.message.KeyExchangeInitializationMessage;

import java.net.InetAddress;

public class KeyExchangeInitializationMessageTest extends MessageTest<KeyExchangeInitializationMessage> {
    @Override
    protected KeyExchangeInitializationMessage constructMessage() throws Throwable {
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        return new KeyExchangeInitializationMessage(source, destination, KeyExchangeInitializationMessage.SecurityLevel.AUTHENTICATED_ENCRYPTION);
    }
}
