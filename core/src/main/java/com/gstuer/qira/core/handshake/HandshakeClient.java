package com.gstuer.qira.core.handshake;

import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.time.Duration;

public class HandshakeClient implements AutoCloseable {
    private static final Duration CLOSE_LINGER = Duration.ofSeconds(5);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(5);

    private final JsonProcessor jsonProcessor = new JsonProcessor();
    private final Socket socket;
    private final PrintWriter out;
    private final BufferedReader in;

    public HandshakeClient(InetAddress host, int port) throws IOException {
        this.socket = new Socket(host, port);
        this.out = new PrintWriter(this.socket.getOutputStream(), true);
        this.in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

        // Configure socket
        this.socket.setSoTimeout((int) READ_TIMEOUT.toMillis());
        this.socket.setSoLinger(true, (int) CLOSE_LINGER.toSeconds());
    }

    public HandshakeClient(Socket socket) throws IOException {
        this.socket = socket;
        if (!socket.isConnected() || socket.isClosed()) {
            throw new IllegalArgumentException("Invalid uninitialized or closed socket.");
        }
        this.out = new PrintWriter(this.socket.getOutputStream(), true);
        this.in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

        // Configure socket
        this.socket.setSoTimeout((int) READ_TIMEOUT.toMillis());
        this.socket.setSoLinger(true, (int) CLOSE_LINGER.toSeconds());
    }

    public void sendRaw(String request) {
        this.out.println(request);
    }

    public String receiveRaw() throws IOException {
        return this.in.readLine();
    }

    public void sendJson(Object request) throws SerializationException {
        String json = jsonProcessor.convertToJson(request);
        this.sendRaw(json);
    }

    public <T> T receiveJson(Class<T> responseType) throws IOException, SerializationException {
        String json = this.receiveRaw();
        return jsonProcessor.convertToObject(json, responseType);
    }

    public String sendAndReceiveRaw(String request) throws IOException {
        sendRaw(request);
        return receiveRaw();
    }

    public <T> T sendAndReceiveJson(Object request, Class<T> responseType) throws IOException, SerializationException {
        sendJson(request);
        return receiveJson(responseType);
    }

    @Override
    public void close() throws IOException {
        this.socket.close();
    }

    public InetAddress getLocalAddress() {
        return this.socket.getLocalAddress();
    }

    public InetAddress getRemoteAddress() {
        return this.socket.getInetAddress();
    }

    protected JsonProcessor getJsonProcessor() {
        return this.jsonProcessor;
    }
}
