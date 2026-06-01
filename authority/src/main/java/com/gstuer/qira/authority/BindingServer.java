package com.gstuer.qira.authority;

import com.gstuer.qira.core.cryptography.signature.Signer;
import com.gstuer.qira.core.handshake.AuthenticatedHandshakeClient;
import com.gstuer.qira.core.handshake.HandshakeException;
import com.gstuer.qira.core.handshake.HandshakeServer;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.BindingQueryRequest;
import com.gstuer.qira.core.message.BindingQueryResponse;
import com.gstuer.qira.core.message.BindingRegistrationRequest;
import com.gstuer.qira.core.message.BindingRegistrationResponse;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Optional;

public class BindingServer extends HandshakeServer {
    private static final int SERVER_PORT = 10010;

    private final Signer<?> signer;
    private final BindingRepository repository;

    public BindingServer(Signer<?> signer) {
        super(SERVER_PORT);
        this.signer = Objects.requireNonNull(signer);
        this.repository = new BindingRepository();
    }

    @Override
    protected void handle(Socket clientSocket) {
        try (AuthenticatedHandshakeClient client = new AuthenticatedHandshakeClient(clientSocket)) {
            client.setSigner(this.signer);
            AuthenticatedMessage authenticatedMessage = client.receiveJson(AuthenticatedMessage.class);
            if (authenticatedMessage.getPayload() instanceof BindingRegistrationRequest payload) {
                // Step 1: Receive & verify binding registration request
                client.setVerifier(payload.getPayload().getVerifier());
                BindingRegistrationRequest registrationMessage = client
                        .verifyAndUnpackAuthenticatedMessage(authenticatedMessage, BindingRegistrationRequest.class);
                IdentityBinding identityBinding = registrationMessage.getPayload();

                // Step 2: Add binding to repository
                BindingRegistrationResponse responseMessage;
                if (this.repository.existsBinding(identityBinding)) {
                    System.out.printf("[Binding Server] Binding already exists <%s,%s>.\n", identityBinding.getEnforcerIdentity(), identityBinding.getGuardedIdentity());
                    responseMessage = new BindingRegistrationResponse(client.getLocalAddress(), identityBinding.getEnforcerIdentity(), BindingRegistrationResponse.ResponseType.EXISTS);
                } else if (this.repository.addBinding(identityBinding)) {
                    System.out.printf("[Binding Server] Registered new binding <%s,%s>.\n", identityBinding.getEnforcerIdentity(), identityBinding.getGuardedIdentity());
                    responseMessage = new BindingRegistrationResponse(client.getLocalAddress(), identityBinding.getEnforcerIdentity(), BindingRegistrationResponse.ResponseType.CREATED);
                } else {
                    // TODO Add possibility to update public key in binding
                    System.err.printf("[Binding Server] Binding conflict for <%s,%s>.\n", identityBinding.getEnforcerIdentity(), identityBinding.getGuardedIdentity());
                    responseMessage = new BindingRegistrationResponse(client.getLocalAddress(), identityBinding.getEnforcerIdentity(), BindingRegistrationResponse.ResponseType.FAILED);
                }

                // Step 3: Send response message to requestor
                client.sendAuthenticatedMessage(responseMessage);
            } else if (authenticatedMessage.getPayload() instanceof BindingQueryRequest) {
                // Step 1: Verify signature with verifier from repository
                Optional<IdentityBinding> optionalBinding = this.repository.getBindingByEnforcerIdentity(client.getRemoteAddress());
                if (optionalBinding.isEmpty()) {
                    throw new HandshakeException("Binding query from unregistered entity.");
                }
                client.setVerifier(optionalBinding.get().getVerifier());
                BindingQueryRequest queryRequest = client.verifyAndUnpackAuthenticatedMessage(authenticatedMessage, BindingQueryRequest.class);

                // Step 2: Query binding repository & build response message
                BindingQueryResponse responseMessage = new BindingQueryResponse(client.getLocalAddress(),
                        optionalBinding.get().getEnforcerIdentity(), this.repository.query(queryRequest.getPayload()));

                // Step 3: Send response message to requestor
                client.sendAuthenticatedMessage(responseMessage);
                System.out.printf("[Binding Server] Responded to identity query: %s.\n", queryRequest.getPayload());
            } else {
                throw new HandshakeException("Initial request not supported: " + authenticatedMessage);
            }
        } catch (IOException | SerializationException | SignatureException | HandshakeException | InvalidKeyException exception) {
            System.out.println("[Binding Server] Externally-initiated handshake failed: " + exception);
        }
    }
}