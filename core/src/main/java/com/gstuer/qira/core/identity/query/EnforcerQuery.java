package com.gstuer.qira.core.identity.query;

import com.gstuer.qira.core.identity.IdentityBinding;

import java.io.Serial;
import java.net.InetAddress;
import java.util.Objects;
import java.util.function.Predicate;

public class EnforcerQuery extends IdentityQuery {
    @Serial
    private static final long serialVersionUID = 4886241484591856238L;

    private final InetAddress enforcerIdentity;

    public EnforcerQuery(InetAddress enforcerIdentity) {
        this.enforcerIdentity = Objects.requireNonNull(enforcerIdentity);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        EnforcerQuery that = (EnforcerQuery) object;
        return enforcerIdentity.equals(that.enforcerIdentity);
    }

    @Override
    public int hashCode() {
        return enforcerIdentity.hashCode();
    }

    @Override
    protected Predicate<IdentityBinding> getQueryPredicate() {
        return binding -> enforcerIdentity.equals(binding.getEnforcerIdentity());
    }
}
