package com.gstuer.qira.core.encapsulation;

import java.io.Serial;

public class EncapsulationException extends Exception {
    @Serial
    private static final long serialVersionUID = 5506397019044882102L;

    public EncapsulationException() {}

    public EncapsulationException(String message) {
        super(message);
    }

    public EncapsulationException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncapsulationException(Throwable cause) {
        super(cause);
    }
}
