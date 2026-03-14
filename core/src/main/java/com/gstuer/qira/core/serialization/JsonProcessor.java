package com.gstuer.qira.core.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.gstuer.qira.core.message.AuthenticatedMessage;
import com.gstuer.qira.core.message.EncryptedMessage;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.pcap4j.packet.Packet;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

        // Type factory for messages
        RuntimeTypeAdapterFactory<?> messageAdapterFactory = RuntimeTypeAdapterFactory
                .of(Message.class)
                .registerSubtype(AuthenticatedMessage.class)
                .registerSubtype(EncryptedMessage.class)
                .registerSubtype(PayloadExchangeMessage.class)
//                .registerSubtype(KeyExchangeMessage.class)
//                .registerSubtype(KeyEstablishmentRequestMessage.class)
//                .registerSubtype(KeyEstablishmentResponseMessage.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(messageAdapterFactory);
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
