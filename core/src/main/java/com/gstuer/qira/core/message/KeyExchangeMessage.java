package com.gstuer.qira.core.message;

import com.gstuer.qira.core.cryptography.EncodedKey;

import java.io.Serial;
import java.net.InetAddress;

public class KeyExchangeMessage extends Message<EncodedKey> {
    @Serial
    private static final long serialVersionUID = -7917201188543863223L;

    public KeyExchangeMessage(InetAddress source, InetAddress destination, EncodedKey payload) {
        super(source, destination, payload);
    }

    public KeyExchangeMessage(InetAddress destination, EncodedKey payload) {
        super(destination, payload);
    }

    @Override
    public KeyExchangeMessage fromSource(InetAddress source) {
        return new KeyExchangeMessage(source, this.getDestination(), this.getPayload());
    }
}
