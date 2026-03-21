package com.gstuer.qira.core.identity.query;

import com.gstuer.qira.core.identity.IdentityBinding;
import org.pcap4j.util.MacAddress;

import java.io.Serial;
import java.util.Objects;
import java.util.function.Predicate;

public class GuardedQuery extends IdentityQuery {
    @Serial
    private static final long serialVersionUID = 5058130015080391483L;

    private final MacAddress guardedIdentity;

    public GuardedQuery(MacAddress guardedIdentity) {
        this.guardedIdentity = Objects.requireNonNull(guardedIdentity);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        GuardedQuery that = (GuardedQuery) object;
        return guardedIdentity.equals(that.guardedIdentity);
    }

    @Override
    public int hashCode() {
        return guardedIdentity.hashCode();
    }

    @Override
    protected Predicate<IdentityBinding> getQueryPredicate() {
        // In case of multicast/broadcast query fits all bindings
        if (guardedIdentity.isUnicast()) {
            return binding -> guardedIdentity.equals(binding.getGuardedIdentity());
        } else {
            return _ -> true;
        }
    }
}
