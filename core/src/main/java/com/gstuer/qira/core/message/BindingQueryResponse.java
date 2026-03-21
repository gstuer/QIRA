package com.gstuer.qira.core.message;

import com.gstuer.qira.core.identity.IdentityBinding;

import java.io.Serial;
import java.net.InetAddress;
import java.util.Set;

public class BindingQueryResponse extends Message<Set<IdentityBinding>> {
    @Serial
    private static final long serialVersionUID = 2646983402356435218L;

    public BindingQueryResponse(InetAddress source, InetAddress destination, Set<IdentityBinding> bindings) {
        super(source, destination, bindings);
    }

    public BindingQueryResponse(InetAddress destination, Set<IdentityBinding> bindings) {
        super(destination, bindings);
    }

    @Override
    public Message<Set<IdentityBinding>> fromSource(InetAddress source) {
        return new BindingQueryResponse(source, this.getDestination(), this.getPayload());
    }
}
