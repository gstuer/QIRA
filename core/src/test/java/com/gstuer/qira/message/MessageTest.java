package com.gstuer.qira.message;

import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.JsonProcessor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class MessageTest<T extends Message<?>> {
    @Test
    public void testSerializationAndDeserializationOfMessage() throws Throwable {
        T message = this.constructMessage();
        JsonProcessor jsonProcessor = new JsonProcessor();

        // Serialize message
        System.out.println(jsonProcessor.convertToJson(message));
        byte[] serialMessage = jsonProcessor.serialize(message);

        // Deserialize message
        T deserialMessage = (T) jsonProcessor.deserialize(serialMessage, Message.class);
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    protected abstract T constructMessage() throws Throwable;
}
