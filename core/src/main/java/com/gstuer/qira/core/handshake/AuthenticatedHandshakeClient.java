package com.gstuer.qira.core.handshake;

import com.gstuer.qira.core.cryptography.signature.Signer;
import com.gstuer.qira.core.cryptography.signature.Verifier;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class AuthenticatedHandshakeClient extends HandshakeClient {
    private Signer<?> signer;
    private Verifier<?> verifier;

    public AuthenticatedHandshakeClient(InetAddress host, int port) throws IOException {
        super(host, port);
    }

    public AuthenticatedHandshakeClient(Socket socket) throws IOException {
        super(socket);
    }

    public void setSigner(Signer<?> signer) {
        this.signer = signer;
    }

    public void setVerifier(Verifier<?> verifier) {
        this.verifier = verifier;
    }

    public void sendAuthenticatedMessage(Message<?> message) throws SerializationException, SignatureException, InvalidKeyException {
        message = message.sign(signer);
        super.sendJson(message);
    }

    public <T extends Message<?>> T receiveAuthenticatedMessage(Class<T> messageType) throws SerializationException, IOException,
            HandshakeException, SignatureException {
        AuthenticatedMessage message = super.receiveJson(AuthenticatedMessage.class);
        return this.verifyAndUnpackAuthenticatedMessage(message, messageType);
    }

    public <T extends Message<?>> T sendAndReceiveAuthenticatedMessage(Message<?> message, Class<T> messageType) throws SerializationException, SignatureException, InvalidKeyException, IOException, HandshakeException {
        this.sendAuthenticatedMessage(message);
        return this.receiveAuthenticatedMessage(messageType);
    }

    public <T> T verifyAndUnpackAuthenticatedMessage(AuthenticatedMessage authenticatedMessage,
                                                      Class<T> expectedNestedMessageType) throws SignatureException, HandshakeException {
        // Check signature of message
        if (!authenticatedMessage.hasConsistentSource(this.getRemoteAddress())) {
            throw new SignatureException("Inconsistent source of message. Source spoofing possible.");
        } else if (!authenticatedMessage.hasConsistentDestination(this.getLocalAddress())) {
            throw new SignatureException("Inconsistent destination of message. Destination spoofing possible.");
        } else if (!authenticatedMessage.verify(this.verifier)) {
            throw new SignatureException("Verification of request signature failed.");
        }

        // Check payload type of message
        if (expectedNestedMessageType.isInstance(authenticatedMessage.getPayload())) {
            return expectedNestedMessageType.cast(authenticatedMessage.getPayload());
        } else {
            throw new HandshakeException("Invalid request payload type: Expected "
                    + expectedNestedMessageType.getCanonicalName() + ", but was "
                    + authenticatedMessage.getPayload().getClass().getCanonicalName());
        }
    }
}
