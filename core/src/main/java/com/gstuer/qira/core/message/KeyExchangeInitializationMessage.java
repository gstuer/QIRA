package com.gstuer.qira.core.message;

import java.io.Serial;
import java.net.InetAddress;
import java.util.Objects;

public class KeyExchangeInitializationMessage extends Message<KeyExchangeInitializationMessage.SecurityLevel> {
    @Serial
    private static final long serialVersionUID = -5044324242053725495L;

    public KeyExchangeInitializationMessage(InetAddress source, InetAddress destination, SecurityLevel payload) {
        super(source, destination, Objects.requireNonNull(payload));
    }

    public KeyExchangeInitializationMessage(InetAddress destination, SecurityLevel payload) {
        super(destination, Objects.requireNonNull(payload));
    }

    @Override
    public KeyExchangeInitializationMessage fromSource(InetAddress source) {
        return new KeyExchangeInitializationMessage(source, this.getDestination(), this.getPayload());
    }

    public enum SecurityLevel {
        AUTHENTICATION,
        AUTHENTICATED_ENCRYPTION;
    }
}
