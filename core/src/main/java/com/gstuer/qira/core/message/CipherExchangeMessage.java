package com.gstuer.qira.core.message;

import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;

import java.io.Serial;
import java.net.InetAddress;

public class CipherExchangeMessage extends Message<KeyedMessageEncapsulator<?, ?>> {
    @Serial
    private static final long serialVersionUID = -7917201188543863223L;

    public CipherExchangeMessage(InetAddress source, InetAddress destination, KeyedMessageEncapsulator<?, ?> payload) {
        super(source, destination, payload);
    }

    public CipherExchangeMessage(InetAddress destination, KeyedMessageEncapsulator<?, ?> payload) {
        super(destination, payload);
    }

    @Override
    public CipherExchangeMessage fromSource(InetAddress source) {
        return new CipherExchangeMessage(source, this.getDestination(), this.getPayload());
    }
}
