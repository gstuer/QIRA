package com.gstuer.qira.enforcer.security;

import com.google.common.io.Files;
import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.Verifier;
import com.gstuer.qira.core.cryptography.signature.algorithm.HmacSHA256;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.ChaCha20Poly1305;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.handshake.AuthenticatedHandshakeClient;
import com.gstuer.qira.core.handshake.HandshakeException;
import com.gstuer.qira.core.handshake.HandshakeServer;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.identity.query.EnforcerQuery;
import com.gstuer.qira.core.identity.query.GuardedQuery;
import com.gstuer.qira.core.identity.query.IdentityQuery;
import com.gstuer.qira.core.message.BindingQueryRequest;
import com.gstuer.qira.core.message.BindingQueryResponse;
import com.gstuer.qira.core.message.BindingRegistrationRequest;
import com.gstuer.qira.core.message.BindingRegistrationResponse;
import com.gstuer.qira.core.message.CipherExchangeMessage;
import com.gstuer.qira.core.message.KeyExchangeInitializationMessage;
import com.gstuer.qira.core.message.KeyExchangeMessage;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;
import org.apache.commons.lang3.tuple.Pair;
import org.pcap4j.util.MacAddress;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class KeyLibrary {
    private static final File AUTHENTICATOR_FILE = new File("./authenticator_cep.json");
    private static final String KEM_ALGORITHM_IDENTIFIER = "ML-KEM-1024";
    private static final int KEY_EXCHANGE_SERVER_PORT = 10008;

    private final InetAddress identityAuthorityAddress;
    private final int identityAuthorityPort;
    private final Verifier<?> identityAuthorityVerifier;

    private final Authenticator<?, ?> ownAuthenticator;
    private final IdentityBinding ownBinding;

    private final Set<IdentityBinding> externalBindings;
    private final HashMap<InetAddress, KeyedMessageEncapsulator<?, ?>> messageDecapsulators;
    private final HashMap<MacAddress, Pair<InetAddress, KeyedMessageEncapsulator<?, ?>>> messageEncapsulators;

    private final KeyExchangeServer keyExchangeServer;

    public KeyLibrary(InetAddress ownExternalAddress, MacAddress guardedEntity, InetAddress identityAuthorityAddress, int identityAuthorityPort, Verifier<?> identityAuthorityVerifier) {
        this.identityAuthorityAddress = Objects.requireNonNull(identityAuthorityAddress);
        this.identityAuthorityPort = identityAuthorityPort;
        this.identityAuthorityVerifier = Objects.requireNonNull(identityAuthorityVerifier);
        this.externalBindings = new HashSet<>();
        this.messageDecapsulators = new HashMap<>();
        this.messageEncapsulators = new HashMap<>();

        // Load identity authenticating material or generate and persist
        JsonProcessor jsonProcessor = new JsonProcessor();
        if (AUTHENTICATOR_FILE.exists()) {
            try {
                String jsonAuthenticator = Files.asCharSource(AUTHENTICATOR_FILE, JsonProcessor.getDefaultCharset()).read();
                this.ownAuthenticator = jsonProcessor.convertToObject(jsonAuthenticator, Authenticator.class);
            } catch (IOException | SerializationException exception) {
                throw new IllegalStateException("[Key Library] Identity authenticator file not readable. Please delete file to generate new authenticator.", exception);
            }
        } else {
            // Generate new authenticator
            this.ownAuthenticator = new MLDSA87();
            this.ownAuthenticator.initializeKeyPair();

            // Write authenticator to file
            try {
                Files.asCharSink(AUTHENTICATOR_FILE, JsonProcessor.getDefaultCharset()).write(jsonProcessor.convertToJson(this.ownAuthenticator));
            } catch (IOException | SerializationException exception) {
                throw new IllegalStateException("[Key Library] Identity authenticator file not writable.", exception);
            }
        }

        // Create own binding locally
        this.ownBinding = new IdentityBinding(Objects.requireNonNull(ownExternalAddress),
                Objects.requireNonNull(guardedEntity), this.ownAuthenticator.getShareableVerifier());

        // Create key exchange server
        this.keyExchangeServer = new KeyExchangeServer();
    }


    public BindingRegistrationResponse.ResponseType registerIdentity() throws HandshakeException {
        // Establish TCP connection to IA
        try (AuthenticatedHandshakeClient authorityClient = new AuthenticatedHandshakeClient(identityAuthorityAddress, identityAuthorityPort)) {
            // Setup handshake authentication
            authorityClient.setSigner(this.ownAuthenticator);
            authorityClient.setVerifier(this.identityAuthorityVerifier);

            // Send authenticated identity binding request to IA & receive binding response
            BindingRegistrationRequest registrationMessage = new BindingRegistrationRequest(this.ownBinding.getEnforcerIdentity(),
                    this.identityAuthorityAddress, this.ownBinding);
            BindingRegistrationResponse bindingResponseMessage = authorityClient
                    .sendAndReceiveAuthenticatedMessage(registrationMessage, BindingRegistrationResponse.class);

            return bindingResponseMessage.getPayload();
        } catch (IOException | SerializationException | SignatureException | InvalidKeyException | HandshakeException exception) {
            throw new HandshakeException("[Key Library] Identity binding failed.", exception);
        }
    }

    public Optional<IdentityBinding> resolveIdentity(EnforcerQuery query) throws HandshakeException {
        // TODO Check for conflicts to guarantee result is conflict-free (see binding repository)
        return this.resolveIdentity((IdentityQuery) query).stream().findFirst();
    }

    public Set<IdentityBinding> resolveIdentity(IdentityQuery query) throws HandshakeException {
        // Perform local lookup
        Set<IdentityBinding> bindings = this.externalBindings.parallelStream()
                .filter(query::fits)
                .collect(Collectors.toUnmodifiableSet());

        // Return if bindings were found
        if (!bindings.isEmpty()) {
            return bindings;
        } else {
            // Perform remote lookup at IA
            try (AuthenticatedHandshakeClient authorityClient = new AuthenticatedHandshakeClient(identityAuthorityAddress, identityAuthorityPort)) {
                // Setup handshake authentication
                authorityClient.setSigner(this.ownAuthenticator);
                authorityClient.setVerifier(this.identityAuthorityVerifier);

                // Send authenticated identity query request to IA & receive query response
                BindingQueryRequest queryMessage = new BindingQueryRequest(this.ownBinding.getEnforcerIdentity(),
                        this.identityAuthorityAddress, query);
                BindingQueryResponse queryResponse = authorityClient.sendAndReceiveAuthenticatedMessage(queryMessage, BindingQueryResponse.class);

                // Add queried bindings to local lookup set
                Set<IdentityBinding> queriedBindings = queryResponse.getPayload();
                this.externalBindings.addAll(queriedBindings);
                return queriedBindings;
            } catch (IOException | SerializationException | SignatureException | InvalidKeyException |
                     HandshakeException exception) {
                throw new HandshakeException("[Key Library] Identity resolution failed.", exception);
            }
        }
    }

    public Optional<KeyedMessageEncapsulator<?, ?>> getMessageDecapsulator(InetAddress enforcerIdentity) {
        // If local lookup fails, ignore
        // TODO Maybe send rejected status message via async UDP data plane to inform sender
        return Optional.ofNullable(this.messageDecapsulators.get(enforcerIdentity));
    }

    public Collection<Pair<InetAddress, KeyedMessageEncapsulator<?, ?>>> getTuplesDEM(MacAddress receiverAddress) {
        if (!receiverAddress.isUnicast() && !this.messageEncapsulators.isEmpty()) {
            // TODO Update broadcast/multicast bindings periodically
            // If address is multicast or broadcast, return all encapsulators
            return this.messageEncapsulators.values();
        }

        // If address is unicast, perform lookup for specific enforcer
        try {
            // Perform local lookup
            Pair<InetAddress, KeyedMessageEncapsulator<?, ?>> localEncapsulator = this.messageEncapsulators.get(receiverAddress);
            if (Objects.isNull(localEncapsulator)) {
                // Establish new key if necessary
                GuardedQuery guardedQuery = new GuardedQuery(receiverAddress);
                Set<IdentityBinding> enforcerBindings = this.resolveIdentity(guardedQuery);
                List<Pair<InetAddress, KeyedMessageEncapsulator<?, ?>>> establishedEncapsulators = new ArrayList<>();

                // Establish new bindings in parallel
                enforcerBindings.parallelStream().forEach(binding -> {
                    try {
                        establishedEncapsulators.add(Pair.of(binding.getEnforcerIdentity(), this.establishDataEncapsulationKey(binding)));
                    } catch (HandshakeException exception) {
                        System.out.println("[Key Library] DEM establishment with " + binding.getEnforcerIdentity() + " failed.");
                        exception.printStackTrace();
                    }
                });
                return establishedEncapsulators;
            } else {
                return List.of(localEncapsulator);
            }
        } catch (HandshakeException exception) {
            System.out.println("[Key Library] Message encapsulator retrieval failed.");
            exception.printStackTrace();
            return List.of();
        }
    }

    public void startKeyExchangeServer() {
        this.keyExchangeServer.start();
    }

    public void stopKeyExchangeServer() throws IOException {
        this.keyExchangeServer.stop();
    }

    private KeyedMessageEncapsulator<?, ?> establishDataEncapsulationKey(IdentityBinding receiverBinding) throws HandshakeException {
        // Step 0: Connect to enforcer's key exchange server
        try (AuthenticatedHandshakeClient client = new AuthenticatedHandshakeClient(receiverBinding.getEnforcerIdentity(), KEY_EXCHANGE_SERVER_PORT)) {
            // Step 1: Set signer and verifier for handshaking
            client.setSigner(this.ownAuthenticator);
            client.setVerifier(receiverBinding.getVerifier());

            // Step 2: Send KEM request to DEP_j & receive PK_KEM_DEP_ij
            // TODO Make changing of sec level easier, i.e. more crypto agile
            KeyExchangeInitializationMessage initializationMessage = new KeyExchangeInitializationMessage(this.ownBinding.getEnforcerIdentity(),
                    receiverBinding.getEnforcerIdentity(), KeyExchangeInitializationMessage.SecurityLevel.AUTHENTICATED_ENCRYPTION);
            KeyExchangeMessage publicKeyMessage = client.sendAndReceiveAuthenticatedMessage(initializationMessage, KeyExchangeMessage.class);

            // Step 2: Perform KEM encapsulation, i.e., derive shared DEM key SK_DEM_ij
            EncodedKey encodedPublicKey = publicKeyMessage.getPayload();
            PublicKey publicKey = KeyFactory.getInstance(encodedPublicKey.getAlgorithmIdentifier())
                    .generatePublic(new X509EncodedKeySpec(encodedPublicKey.getKey()));
            KEM.Encapsulator keyEncapsulator = KEM.getInstance(encodedPublicKey.getAlgorithmIdentifier())
                    .newEncapsulator(publicKey);
            KEM.Encapsulated encapsulatedKey = keyEncapsulator.encapsulate();

            // Step 3: Send KEM-encapsulated private DEM key SK_DEM_ij & Receive DEM_ij cipher
            EncodedKey encapsulatedPrivateKey = new EncodedKey(encodedPublicKey.getAlgorithmIdentifier(), encapsulatedKey.encapsulation());
            KeyExchangeMessage encapsulationMessage = new KeyExchangeMessage(this.ownBinding.getEnforcerIdentity(), receiverBinding.getEnforcerIdentity(), encapsulatedPrivateKey);
            CipherExchangeMessage cipherExchangeMessage = client.sendAndReceiveAuthenticatedMessage(encapsulationMessage, CipherExchangeMessage.class);

            // Step 4: Initialize DEM_ij
            SecretKey secretKey = encapsulatedKey.key();
            KeyedMessageEncapsulator<SecretKey, SecretKey> outgoingEncapsulator = (KeyedMessageEncapsulator<SecretKey, SecretKey>) cipherExchangeMessage.getPayload();
            outgoingEncapsulator.setEncapsulationKey(secretKey);

            // Step 5: Persist DEM_ij in library
            this.messageEncapsulators.put(receiverBinding.getGuardedIdentity(), Pair.of(receiverBinding.getEnforcerIdentity(), outgoingEncapsulator));
            System.out.println("[Key Library] Self-initiated DEM with " + receiverBinding.getEnforcerIdentity() + " established.");
            return outgoingEncapsulator;
        } catch (IOException | SerializationException | SignatureException |
                 NoSuchAlgorithmException | InvalidKeySpecException | HandshakeException | InvalidKeyException exception) {
            throw new HandshakeException("[Key Library] Self-initiated key exchange handshake failed.", exception);
        }
    }

    private final class KeyExchangeServer extends HandshakeServer {
        public KeyExchangeServer() {
            super(KEY_EXCHANGE_SERVER_PORT);
        }

        @Override
        protected void handle(Socket clientSocket) {
            try (AuthenticatedHandshakeClient requestorClient = new AuthenticatedHandshakeClient(clientSocket)) {
                // Step 1: Resolve identity of requestor & set signer/verifier
                Optional<IdentityBinding> optionalBinding = KeyLibrary.this.resolveIdentity(new EnforcerQuery(requestorClient.getRemoteAddress()));
                IdentityBinding binding;
                if (optionalBinding.isEmpty()) {
                    throw new HandshakeException("Identity resolution failed due to missing binding.");
                } else {
                    binding = optionalBinding.get();
                    if (!binding.getEnforcerIdentity().equals(requestorClient.getRemoteAddress())) {
                        throw new HandshakeException("Identity resolution returned non-sender binding.");
                    }
                    requestorClient.setSigner(KeyLibrary.this.ownAuthenticator);
                    requestorClient.setVerifier(binding.getVerifier());
                }

                // Step 2: Receive and verify KEM request from DEP_i
                KeyExchangeInitializationMessage keyExchangeInitializationMessage = requestorClient
                        .receiveAuthenticatedMessage(KeyExchangeInitializationMessage.class);

                // Step 3: Extract requested key type
                KeyExchangeInitializationMessage.SecurityLevel requestedSecurityLevel = keyExchangeInitializationMessage.getPayload();

                // Step 4: Generate KEM_DEP_j keypair & encode PK_KEM_DEP_ij
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_ALGORITHM_IDENTIFIER);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                KeyFactory keyFactory = KeyFactory.getInstance(KEM_ALGORITHM_IDENTIFIER);
                X509EncodedKeySpec x509EncodedPublicKey = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
                EncodedKey encodedKey = new EncodedKey(KEM_ALGORITHM_IDENTIFIER, x509EncodedPublicKey.getEncoded());

                // Step 5: Send PK_KEM_DEP_ij to DEP_i & Receive KEM-encapsulated private DEM key SK_DEM_ij
                KeyExchangeMessage publicKeyMessage = new KeyExchangeMessage(KeyLibrary.this.ownBinding.getEnforcerIdentity(),
                        keyExchangeInitializationMessage.getSource(), encodedKey);
                KeyExchangeMessage encapsulationMessage = requestorClient.sendAndReceiveAuthenticatedMessage(publicKeyMessage, KeyExchangeMessage.class);

                // Step 7: Decapsulate SK_DEM_ij with SK_KEM_DEP_j
                KEM.Decapsulator keyDecapsulator = KEM.getInstance(KEM_ALGORITHM_IDENTIFIER).newDecapsulator(keyPair.getPrivate());
                SecretKey secretKey = keyDecapsulator.decapsulate(encapsulationMessage.getPayload().getKey());

                // Step 8: Initialize DEM_ij
                KeyedMessageEncapsulator<SecretKey, SecretKey> incomingDecapsulator;
                KeyedMessageEncapsulator<SecretKey, SecretKey> outgoingEncapsulator;
                if (requestedSecurityLevel == KeyExchangeInitializationMessage.SecurityLevel.AUTHENTICATION) {
                    // TODO Make changing easier, i.e. more crypto agile
                    incomingDecapsulator = new HmacSHA256();
                    outgoingEncapsulator = new HmacSHA256();
                } else if (requestedSecurityLevel == KeyExchangeInitializationMessage.SecurityLevel.AUTHENTICATED_ENCRYPTION) {
                    // TODO Make changing easier, i.e. more crypto agile
                    incomingDecapsulator = new ChaCha20Poly1305();
                    outgoingEncapsulator = new ChaCha20Poly1305();
                } else {
                    throw new HandshakeException("Unsupported DEM security level requested.");
                }

                // Step 9: Set SK_DEM_ij in DEM_ij (incoming only!) & persist in library
                incomingDecapsulator.setDecapsulationKey(secretKey);
                KeyLibrary.this.messageDecapsulators.put(binding.getEnforcerIdentity(), incomingDecapsulator);

                // Step 10: Send outgoing encapsulator (w/o secret) to requestor
                // Note: This has to be the last step, otherwise a server exception could be undetected by the requestor.
                // However, if there is a client-side exception the requestor is able to restart the procedure at any time.
                requestorClient.sendAuthenticatedMessage(new CipherExchangeMessage(KeyLibrary.this.ownBinding.getEnforcerIdentity(),
                        keyExchangeInitializationMessage.getSource(), outgoingEncapsulator));
                System.out.println("[Key Library] Externally-initiated DEM with " + keyExchangeInitializationMessage.getSource() + " established.");
            } catch (IOException | SerializationException | SignatureException | NoSuchAlgorithmException
                     | InvalidKeySpecException | HandshakeException | InvalidKeyException | DecapsulateException exception) {
                System.out.println("[Key Library] Externally-initiated key exchange handshake failed: " + exception);
            }
        }
    }
}
