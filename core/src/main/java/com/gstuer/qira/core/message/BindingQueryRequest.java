package com.gstuer.qira.core.message;

import com.gstuer.qira.core.identity.query.IdentityQuery;

import java.io.Serial;
import java.net.InetAddress;

public class BindingQueryRequest extends Message<IdentityQuery> {
    @Serial
    private static final long serialVersionUID = 1941450749253870288L;

    public BindingQueryRequest(InetAddress source, InetAddress destination, IdentityQuery payload) {
        super(source, destination, payload);
    }

    public BindingQueryRequest(InetAddress destination, IdentityQuery payload) {
        super(destination, payload);
    }

    @Override
    public Message<IdentityQuery> fromSource(InetAddress source) {
        return new BindingQueryRequest(source, this.getDestination(), this.getPayload());
    }
}
