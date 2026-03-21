package com.gstuer.qira.message;

import com.gstuer.qira.core.message.BindingRegistrationResponse;

import java.net.InetAddress;

public class BindingRegistrationResponseTest extends MessageTest<BindingRegistrationResponse> {
    @Override
    protected BindingRegistrationResponse constructMessage() throws Throwable {
        InetAddress enforcerIdentity = InetAddress.getByName("127.0.0.1");
        return new BindingRegistrationResponse(enforcerIdentity, BindingRegistrationResponse.ResponseType.CREATED);
    }
}
