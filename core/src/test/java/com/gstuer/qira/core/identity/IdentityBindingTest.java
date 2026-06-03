package com.gstuer.qira.core.identity;

import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.serialization.JsonProcessor;
import org.junit.jupiter.api.Test;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class IdentityBindingTest {
    @Test
    public void testSerializationAndDeserialization() throws Throwable {
        InetAddress enforcerIdentity = InetAddress.getByName("127.0.0.1");
        MacAddress guardedIdentity = MacAddress.getByName("00:00:00:00:00:00");
        Authenticator<?, ?> authenticator = new MLDSA87();
        authenticator.initializeKeyPair();
        IdentityBinding binding = new IdentityBinding(enforcerIdentity, guardedIdentity, authenticator.getShareableVerifier());

        // Serialize
        JsonProcessor jsonProcessor = new JsonProcessor();
        byte[] serialBinding = jsonProcessor.serialize(binding);

        // Deserialize
        IdentityBinding deserialBinding = jsonProcessor.deserialize(serialBinding, IdentityBinding.class);
        assertNotNull(deserialBinding);
        assertEquals(binding, deserialBinding);
    }
}
