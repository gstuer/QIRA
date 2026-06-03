package com.gstuer.qira.core.serialization;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.Verifier;

import java.lang.reflect.Type;

public class VerifierSerializer implements JsonSerializer<Verifier<?>>, JsonDeserializer<Verifier<?>> {
    @Override
    public JsonElement serialize(Verifier src, Type typeOfSrc, JsonSerializationContext context) {
        try {
            return JsonParser.parseString(new JsonProcessor().convertToJson(src, Authenticator.class));
        } catch (SerializationException exception) {
            return null;
        }
    }

    @Override
    public Verifier<?> deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        try {
            return new JsonProcessor().convertToObject(json.toString(), Authenticator.class);
        } catch (SerializationException exception) {
            throw new JsonParseException(exception);
        }
    }
}
