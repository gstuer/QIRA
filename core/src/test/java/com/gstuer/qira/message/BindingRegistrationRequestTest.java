package com.gstuer.qira.message;

import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.message.BindingRegistrationRequest;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

public class BindingRegistrationRequestTest extends MessageTest<BindingRegistrationRequest> {
    @Override
    protected BindingRegistrationRequest constructMessage() throws Throwable {
        InetAddress enforcerIdentity = InetAddress.getByName("127.0.0.1");
        MacAddress guardedIdentity = MacAddress.getByName("00:00:00:00:00:00");

        Authenticator<?, ?> authenticator = new MLDSA87();
        authenticator.initializeKeyPair();
        IdentityBinding binding = new IdentityBinding(enforcerIdentity, guardedIdentity, authenticator.getShareableVerifier());
        return new BindingRegistrationRequest(enforcerIdentity, binding);
    }
}
