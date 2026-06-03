package com.gstuer.qira.core.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.gstuer.qira.core.cryptography.signature.Verifier;
import com.gstuer.qira.core.cryptography.signature.algorithm.AES256GMAC;
import com.gstuer.qira.core.cryptography.signature.algorithm.HmacSHA256;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA44;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA65;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256CCM;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.AES256GCM;
import com.gstuer.qira.core.cryptography.signcryption.algorithm.ChaCha20Poly1305;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.identity.query.EnforcerQuery;
import com.gstuer.qira.core.identity.query.GuardedQuery;
import com.gstuer.qira.core.identity.query.IdentityQuery;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.BindingQueryRequest;
import com.gstuer.qira.core.message.BindingQueryResponse;
import com.gstuer.qira.core.message.BindingRegistrationRequest;
import com.gstuer.qira.core.message.BindingRegistrationResponse;
import com.gstuer.qira.core.message.CipherExchangeMessage;
import com.gstuer.qira.core.message.EncryptedMessage;
import com.gstuer.qira.core.message.KeyExchangeInitializationMessage;
import com.gstuer.qira.core.message.KeyExchangeMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.pcap4j.packet.Packet;

import javax.crypto.SecretKey;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;

public class JsonProcessor {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private final Gson gson;

    public JsonProcessor() {
        this(false);
    }

    public JsonProcessor(boolean prettyPrinting) {
        GsonBuilder builder = new GsonBuilder();

        // Enable pretty printing for debugging purposes
        if (prettyPrinting) {
            builder.setPrettyPrinting();
        }

        // Register custom type adapters to serialize/deserialize objects correctly
        builder.registerTypeAdapter(Packet.class, new PacketSerializer());
        builder.registerTypeAdapter(Instant.class, new InstantSerializer());
        builder.registerTypeAdapter(Duration.class, new DurationSerializer());
        builder.registerTypeAdapter(byte[].class, new ByteArrayAdapter());
        builder.registerTypeAdapter(Verifier.class, new VerifierSerializer());

        // Register hierarchy adapters for key classes
        builder.registerTypeHierarchyAdapter(SecretKey.class, new SecretKeyAdapter());
        builder.registerTypeHierarchyAdapter(PublicKey.class, new PublicKeyAdapter());
        builder.registerTypeHierarchyAdapter(PrivateKey.class, new PrivateKeyAdapter());

        // Type factory for messages
        RuntimeTypeAdapterFactory<?> messageAdapterFactory = RuntimeTypeAdapterFactory
                .of(Message.class)
                .registerSubtype(AuthenticatedMessage.class)
                .registerSubtype(EncryptedMessage.class)
                .registerSubtype(PayloadExchangeMessage.class)
                .registerSubtype(BindingRegistrationRequest.class)
                .registerSubtype(BindingRegistrationResponse.class)
                .registerSubtype(BindingQueryRequest.class)
                .registerSubtype(BindingQueryResponse.class)
                .registerSubtype(CipherExchangeMessage.class)
                .registerSubtype(KeyExchangeMessage.class)
                .registerSubtype(KeyExchangeInitializationMessage.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(messageAdapterFactory);

        // Type factory for identity queries
        RuntimeTypeAdapterFactory<?> identityQueryAdapterFactory = RuntimeTypeAdapterFactory
                .of(IdentityQuery.class)
                .registerSubtype(EnforcerQuery.class)
                .registerSubtype(GuardedQuery.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(identityQueryAdapterFactory);

        // Type factory for message encapsulators
        RuntimeTypeAdapterFactory<?> encapsulatorAdapterFactory = RuntimeTypeAdapterFactory
                .of(KeyedMessageEncapsulator.class)
                .registerSubtype(AES256CCM.class)
                .registerSubtype(AES256GCM.class)
                .registerSubtype(ChaCha20Poly1305.class)
                .registerSubtype(AES256GMAC.class)
                .registerSubtype(HmacSHA256.class)
                .registerSubtype(MLDSA44.class)
                .registerSubtype(MLDSA65.class)
                .registerSubtype(MLDSA87.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(encapsulatorAdapterFactory);

        this.gson = builder.create();
    }

    public static Charset getDefaultCharset() {
        return DEFAULT_CHARSET;
    }

    public String convertToJson(Object object) throws SerializationException {
        try {
            return this.gson.toJson(object);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public String convertToJson(Object object, Type objectType) throws SerializationException {
        try {
            return this.gson.toJson(object, objectType);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public <T> T convertToObject(String json, Class<T> objectClass) throws SerializationException {
        try {
            return this.gson.fromJson(json, objectClass);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public byte[] serialize(Object object) throws SerializationException {
        String json = convertToJson(object);
        return json.getBytes(DEFAULT_CHARSET);
    }

    public <T> T deserialize(byte[] object, Class<T> objectClass) throws SerializationException {
        String json = new String(object, DEFAULT_CHARSET);
        return this.convertToObject(json, objectClass);
    }
}
