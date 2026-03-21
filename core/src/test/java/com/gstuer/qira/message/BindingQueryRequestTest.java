package com.gstuer.qira.message;

import com.gstuer.qira.core.identity.query.GuardedQuery;
import com.gstuer.qira.core.identity.query.IdentityQuery;
import com.gstuer.qira.core.message.BindingQueryRequest;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

public class BindingQueryRequestTest extends MessageTest<BindingQueryRequest> {
    @Override
    protected BindingQueryRequest constructMessage() throws Throwable {
        InetAddress enforcerIdentity = InetAddress.getByName("127.0.0.1");
        MacAddress guardedIdentity = MacAddress.getByName("00:00:00:00:00:00");
        IdentityQuery query = new GuardedQuery(guardedIdentity);
        return new BindingQueryRequest(enforcerIdentity, query);
    }
}
