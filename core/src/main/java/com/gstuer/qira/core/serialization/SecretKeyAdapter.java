package com.gstuer.qira.core.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Base64;

public class SecretKeyAdapter extends TypeAdapter<SecretKey> {
    @Override
    public void write(JsonWriter out, SecretKey value) throws IOException {
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
    public SecretKey read(JsonReader in) throws IOException {
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
        return new SecretKeySpec(key, algorithm);
    }
}
