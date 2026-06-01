package com.gstuer.qira.core.handshake;

import java.io.Serial;

public class HandshakeException extends Exception {
    @Serial
    private static final long serialVersionUID = 7360291964916469737L;

    public HandshakeException() {}

    public HandshakeException(String message) {
        super(message);
    }

    public HandshakeException(String message, Throwable cause) {
        super(message, cause);
    }

    public HandshakeException(Throwable cause) {
        super(cause);
    }
}
