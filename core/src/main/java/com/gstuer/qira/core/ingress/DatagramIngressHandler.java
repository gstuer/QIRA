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
import java.util.Objects;
import java.util.function.Consumer;

public class DatagramIngressHandler extends IngressHandler<Message<?>> {
    private final InetAddress address;
    private final int port;
    private DatagramSocket socket;

    public DatagramIngressHandler(InetAddress address, int port, Consumer<Message<?>> messageConsumer) {
        super(messageConsumer);
        this.address = Objects.requireNonNull(address);
        this.port = port;
    }

    @Override
    public void open() {
        try {
            this.socket = new DatagramSocket(new InetSocketAddress(address, port));
            while (!this.socket.isClosed()) {
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
        // Deserialize message transmitted
        JsonProcessor jsonProcessor = new JsonProcessor();
        Message<?> message;
        try {
            message = jsonProcessor.deserialize(datagram.getData(), Message.class);
        } catch (SerializationException exception) {
            System.err.println("[Ingress Datagram] Deserialization failed: " + exception.getMessage());
            return;
        }

        // Get sender of datagram & check or set sender of message
        InetAddress sender = datagram.getAddress();
        if (!sender.equals(message.getSource())) {
            System.err.println("[Ingress Datagram] Inconsistent source of message. Source spoofing possible.");
            return;
        } else if (!message.getDestination().equals(this.address)) {
            System.err.println("[Ingress Datagram] Inconsistent destination of message. Destination spoofing possible.");
            return;
        }

        super.handle(message);
    }
}
