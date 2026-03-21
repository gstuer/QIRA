package com.gstuer.qira.core.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyAdapter extends TypeAdapter<PublicKey> {
    @Override
    public void write(JsonWriter out, PublicKey value) throws IOException {
        if (value == null) {
            out.nullValue();
            return;
        }
        out.beginObject();
        out.name("algorithm").value(value.getAlgorithm());
        // Encode bytes to Base64 string for JSON safety
        out.name("key").value(Base64.getEncoder().encodeToString(value.getEncoded()));
        out.endObject();
    }

    @Override
    public PublicKey read(JsonReader in) throws IOException {
        String algorithm = null;
        byte[] key = null;

        in.beginObject();
        while (in.hasNext()) {
            switch (in.nextName()) {
                case "algorithm" -> algorithm = in.nextString();
                case "key" -> key = Base64.getDecoder().decode(in.nextString());
            }
        }
        in.endObject();

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(key));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
            throw new IOException(exception);
        }
    }
}
