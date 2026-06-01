package com.gstuer.qira.core.message;

import java.io.Serial;
import java.net.InetAddress;

public class BindingRegistrationResponse extends Message<BindingRegistrationResponse.ResponseType> {
    @Serial
    private static final long serialVersionUID = 3092142320639815104L;

    public BindingRegistrationResponse(InetAddress source, InetAddress destination, ResponseType payload) {
        super(source, destination, payload);
    }

    public BindingRegistrationResponse(InetAddress destination, ResponseType payload) {
        super(destination, payload);
    }

    @Override
    public Message<ResponseType> fromSource(InetAddress source) {
        return new BindingRegistrationResponse(source, this.getDestination(), this.getPayload());
    }

    public enum ResponseType {
        CREATED,
        UPDATED,
        EXISTS,
        FAILED;
    }
}
