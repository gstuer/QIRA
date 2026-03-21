package com.gstuer.qira.authority;

import com.gstuer.qira.core.cryptography.signature.Signer;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.identity.query.IdentityQuery;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.BindingQueryRequest;
import com.gstuer.qira.core.message.BindingQueryResponse;
import com.gstuer.qira.core.message.BindingRegistrationRequest;
import com.gstuer.qira.core.message.BindingRegistrationResponse;
import com.gstuer.qira.core.message.Message;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

public class BindingMessageHandler {
    private final BlockingQueue<Message<?>> messageEgress;
    private final Signer<?> signer;
    private final BindingRepository repository;

    public BindingMessageHandler(BlockingQueue<Message<?>> messageEgress, Signer<?> signer) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.signer = Objects.requireNonNull(signer);
        this.repository = new BindingRepository();
    }

    public void handleRequest(Message<?> request) {
        // Only handle authenticated messages
        if (request instanceof AuthenticatedMessage authenticatedRequest) {
            // Differentiate between binding registration and binding query
            if (authenticatedRequest.getPayload() instanceof BindingRegistrationRequest registrationMessage) {
                // Step 1: Verify signature with verifier from binding
                IdentityBinding binding = registrationMessage.getPayload();
                if (authenticatedRequest.verify(binding.getVerifier())) {
                    // Step 2: Add binding to repository
                    Message<?> response;
                    if (this.repository.addBinding(binding)) {
                        System.out.printf("[IA] Registered new binding <%s,%s>.\n",
                                binding.getEnforcerIdentity(), binding.getGuardedIdentity());
                        response = new BindingRegistrationResponse(binding.getEnforcerIdentity(),
                                BindingRegistrationResponse.ResponseType.CREATED);
                        // TODO Add possibility to update public key in binding
                    } else {
                        System.err.printf("[IA] Binding conflict for <%s,%s>.\n",
                                binding.getEnforcerIdentity(), binding.getGuardedIdentity());
                        response = new BindingRegistrationResponse(binding.getEnforcerIdentity(),
                                BindingRegistrationResponse.ResponseType.FAILED);
                    }

                    // Step 3: Send response message to requestor
                    this.signAndSendMessage(response);
                } else {
                    System.err.println("[IA] Received registration with invalid signature.");
                }
            } else if (authenticatedRequest.getPayload() instanceof BindingQueryRequest queryMessage) {
                // Step 1: Verify signature with verifier from repository
                Optional<IdentityBinding> optionalRequestor = this.repository.getBindingByEnforcerIdentity(queryMessage.getSource());
                if (optionalRequestor.isEmpty()) {
                    System.err.println("[IA] Received query from unbound enforcer.");
                    return;
                }
                IdentityBinding requestor = optionalRequestor.get();
                if (authenticatedRequest.verify(requestor.getVerifier())) {
                    // Step 2: Query binding repository
                    IdentityQuery identityQuery = queryMessage.getPayload();
                    Set<IdentityBinding> bindings = this.repository.query(identityQuery);

                    // Step 3: Build response message
                    Message<?> response = new BindingQueryResponse(requestor.getEnforcerIdentity(), bindings);

                    // Step 4: Send response message to requestor
                    this.signAndSendMessage(response);
                    System.out.printf("[IA] Responded to identity query: %s.\n", queryMessage.getPayload());
                } else {
                    System.err.println("[IA] Received query with invalid signature.");
                }
            } else {
                System.err.printf("[IA] Received unknown message type %s.\n", authenticatedRequest.getPayload().getClass().getCanonicalName());
            }
        } else {
            System.err.println("[IA] Received unauthenticated message.");
        }
    }

    private void signAndSendMessage(Message<?> message) {
        try {
            this.messageEgress.add(message.sign(this.signer));
        } catch (SignatureException | InvalidKeyException exception) {
            System.err.printf("[IA] Signing and sending message failed: %s\n", exception);
        }
    }
}
