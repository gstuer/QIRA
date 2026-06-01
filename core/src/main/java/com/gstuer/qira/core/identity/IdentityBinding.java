package com.gstuer.qira.core.identity;

import com.gstuer.qira.core.cryptography.signature.Verifier;
import org.pcap4j.util.MacAddress;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.Objects;

public class IdentityBinding implements Serializable {
    @Serial
    private static final long serialVersionUID = 6165184188914574606L;

    private final InetAddress enforcerIdentity;
    private final MacAddress guardedIdentity;
    private final Verifier<?> verifier;

    public IdentityBinding(InetAddress enforcerIdentity, MacAddress guardedIdentity, Verifier<?> verifier) {
        this.enforcerIdentity = Objects.requireNonNull(enforcerIdentity);
        this.guardedIdentity = Objects.requireNonNull(guardedIdentity);
        this.verifier = Objects.requireNonNull(verifier);
    }

    public InetAddress getEnforcerIdentity() {
        return this.enforcerIdentity;
    }

    public MacAddress getGuardedIdentity() {
        return guardedIdentity;
    }

    public Verifier<?> getVerifier() {
        return verifier;
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        IdentityBinding binding = (IdentityBinding) object;
        return Objects.equals(this.enforcerIdentity, binding.enforcerIdentity)
                && Objects.equals(this.guardedIdentity, binding.guardedIdentity)
                && Objects.equals(this.verifier, binding.verifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.enforcerIdentity, this.guardedIdentity, this.verifier);
    }
}
