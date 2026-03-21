package com.gstuer.qira.core.identity.query;

import com.gstuer.qira.core.identity.IdentityBinding;

import java.io.Serial;
import java.io.Serializable;
import java.util.function.Predicate;

public abstract class IdentityQuery implements Serializable {
    @Serial
    private static final long serialVersionUID = 2052180517767413681L;

    public boolean fits(IdentityBinding binding) {
        return this.getQueryPredicate().test(binding);
    }

    protected abstract Predicate<IdentityBinding> getQueryPredicate();
}
