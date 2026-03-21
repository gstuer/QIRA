package com.gstuer.qira.core.message;

import com.gstuer.qira.core.identity.IdentityBinding;

import java.io.Serial;
import java.net.InetAddress;

public class BindingRegistrationRequest extends Message<IdentityBinding> {
    @Serial
    private static final long serialVersionUID = 8733143141905925867L;

    public BindingRegistrationRequest(InetAddress source, InetAddress destination, IdentityBinding payload) {
        super(source, destination, payload);
    }

    public BindingRegistrationRequest(InetAddress destination, IdentityBinding payload) {
        super(destination, payload);
    }

    @Override
    public Message<IdentityBinding> fromSource(InetAddress source) {
        return new BindingRegistrationRequest(source, this.getDestination(), this.getPayload());
    }
}
