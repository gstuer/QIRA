package com.gstuer.qira.message;

import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.message.BindingQueryResponse;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.Set;

public class BindingQueryResponseTest extends MessageTest<BindingQueryResponse> {
    @Override
    protected BindingQueryResponse constructMessage() throws Throwable {
        Authenticator<?, ?> authenticator = new MLDSA87();
        authenticator.initializeKeyPair();
        IdentityBinding bindingFirst = new IdentityBinding(InetAddress.getByName("127.0.0.1"), MacAddress.getByName("00:00:00:00:00:00"), authenticator.getShareableVerifier());
        IdentityBinding bindingSecond = new IdentityBinding(InetAddress.getByName("127.0.0.2"), MacAddress.getByName("00:00:00:00:00:00"), authenticator.getShareableVerifier());
        return new BindingQueryResponse(InetAddress.getByName("127.0.0.1"), Set.of(bindingFirst, bindingSecond));
    }
}
