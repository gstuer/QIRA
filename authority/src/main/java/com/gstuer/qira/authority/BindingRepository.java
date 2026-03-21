package com.gstuer.qira.authority;

import com.google.common.collect.Sets;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.identity.query.IdentityQuery;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class BindingRepository {
    private final Set<IdentityBinding> bindings;

    public BindingRepository() {
        this.bindings = Sets.newConcurrentHashSet();
    }

    public boolean addBinding(IdentityBinding binding) {
        boolean hasConflict = this.bindings.parallelStream().anyMatch(otherBinding ->
                binding.getEnforcerIdentity().equals(otherBinding.getEnforcerIdentity())
                    || binding.getGuardedIdentity().equals(otherBinding.getGuardedIdentity())
        );

        if (!hasConflict) {
            this.bindings.add(binding);
            return true;
        }
        return false;
    }

    public Optional<IdentityBinding> getBindingByEnforcerIdentity(InetAddress enforcerIdentity) {
        return this.bindings.parallelStream()
                .filter(binding -> binding.getEnforcerIdentity().equals(enforcerIdentity))
                .findFirst();
    }

    public Optional<IdentityBinding> getBindingByGuardedIdentity(MacAddress guardedIdentity) {
        return this.bindings.parallelStream()
                .filter(binding -> binding.getGuardedIdentity().equals(guardedIdentity))
                .findFirst();
    }

    public Set<IdentityBinding> getBindings() {
        return Collections.unmodifiableSet(this.bindings);
    }

    public Set<IdentityBinding> query(IdentityQuery query) {
        return this.bindings.parallelStream()
                .filter(query::fits)
                .collect(Collectors.toUnmodifiableSet());
    }
}
