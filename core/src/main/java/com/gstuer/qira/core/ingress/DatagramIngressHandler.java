package com.gstuer.qira.core.ingress;

import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.function.Consumer;

public class DatagramIngressHandler extends IngressHandler<Message<?>> {
    private final int port;
    private DatagramSocket socket;

    public DatagramIngressHandler(int port, Consumer<Message<?>> messageConsumer) {
        super(messageConsumer);
        this.port = port;
    }

    @Override
    public void open() {
        DatagramSocket socket;
        try {
            socket = new DatagramSocket(new InetSocketAddress("0.0.0.0", port));
            while (!socket.isClosed()) {
                byte[] buffer = new byte[socket.getReceiveBufferSize()];
                DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagram);

                // Remove "empty" bytes from buffer to avoid deserialization issues
                datagram.setData(new DataInputStream(new ByteArrayInputStream(datagram.getData(), datagram.getOffset(), datagram.getLength())).readAllBytes());
                new Thread(() -> this.handle(datagram)).start();
            }
        } catch (IOException exception) {
            System.err.println("[Ingress Datagram] Binding socket failed: " + exception.getMessage());
            throw new IllegalStateException(exception);
        } finally {
            System.err.println("[Ingress Datagram] Socket closed.");
        }
    }

    @Override
    public void close() {
        this.socket.close();
    }

    protected void handle(DatagramPacket datagram) {
        // Deserialize access control message transmitted
        JsonProcessor jsonProcessor = new JsonProcessor();
        Message<?> message;
        try {
            message = jsonProcessor.deserialize(datagram.getData(), Message.class);
        } catch (SerializationException exception) {
            System.err.println("[Ingress Datagram] Deserialization failed: " + exception.getMessage());
            return;
        }

        // Get sender of datagram and set sender of access control message
        InetAddress sender = datagram.getAddress();
        message = message.fromSource(sender);
        super.handle(message);
    }
}
