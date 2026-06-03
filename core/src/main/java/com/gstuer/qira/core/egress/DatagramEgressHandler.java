package com.gstuer.qira.core.egress;

import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public class DatagramEgressHandler extends EgressHandler<Message<?>> {
    private final InetAddress address;
    private final int sourcePort;
    private final int destinationPort;
    private DatagramSocket socket;

    public DatagramEgressHandler(InetAddress address, int sourcePort, int destinationPort, BlockingQueue<Message<?>> egressQueue) {
        super(egressQueue);
        this.address = Objects.requireNonNull(address);
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
    }

    @Override
    public void open() {
        if (this.isOpen()) {
            throw new IllegalStateException("Handler already open.");
        }

        // Try to open a new datagram socket (UDP communication)
        try {
            socket = new DatagramSocket(new InetSocketAddress(address, this.sourcePort));
        } catch (SocketException exception) {
            throw new IllegalStateException("UDP egress handler cannot be opened for port " + this.sourcePort, exception);
        }

        while (this.isOpen()) {
            Message<?> message;
            try {
                message = takeNextQueueItem();
            } catch (InterruptedException exception) {
                // Handler interrupted during waiting for new packet
                break;
            }
            handle(message);
        }
        System.out.println("[Egress Datagram] Handler closed.");
    }

    @Override
    public void handle(Message<?> message) {
        if (this.socket == null) {
            throw new IllegalStateException("Handler not opened yet.");
        } else if (this.socket.isClosed()) {
            throw new IllegalStateException("Handler already closed.");
        }

        // Add address of socket as source of message if missing
        if (Objects.isNull(message.getSource())) {
            message = message.fromSource(this.address);
        }

        try {
            byte[] serialMessage = new JsonProcessor().serialize(message);
            SocketAddress receiverSocketAddress = new InetSocketAddress(message.getDestination(), this.destinationPort);
            DatagramPacket packet = new DatagramPacket(serialMessage, serialMessage.length, receiverSocketAddress);
            this.socket.send(packet);
        } catch (SerializationException exception) {
            System.out.println("[Egress Datagram] Serialization failed:" + exception.getMessage());
        } catch (IOException exception) {
            System.out.println("[Egress Datagram] Sending failed:" + exception.getMessage());
        }
    }

    @Override
    public void close() {
        this.socket.close();
    }

    public boolean isOpen() {
        return this.socket != null && !this.socket.isClosed();
    }
}
