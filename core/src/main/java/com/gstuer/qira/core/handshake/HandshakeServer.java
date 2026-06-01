package com.gstuer.qira.core.handshake;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.time.Duration;

public abstract class HandshakeServer {
    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(5);
    private final int port;
    private ServerSocket socket;

    protected HandshakeServer(int port) {
        this.port = port;
    }

    public void start() {
        try {
            this.socket = new ServerSocket(this.port);
        } catch (IOException exception) {
            throw new IllegalStateException("[TCP Server] Cannot start listening to socket at port " + this.port, exception);
        }

        while (true) {
            try {
                Socket clientSocket = this.socket.accept();
                new Thread(() -> this.handleContinuously(clientSocket)).start();
            } catch (SocketException exception) {
                // Socket closed gracefully
                break;
            } catch (IOException exception) {
                System.out.println("[TCP Server] Persistent Server Error: " + exception);
                throw new RuntimeException(exception);
            }
        }
    }

    public void stop() throws IOException {
        socket.close();
    }

    private void handleContinuously(Socket clientSocket) {
        try {
            // Configure connection to client
            clientSocket.setSoTimeout((int) CLIENT_TIMEOUT.toMillis());

            // Handle incoming client connection request
            handle(clientSocket);
        } catch (Exception exception) {
            System.out.println("[TCP Server] Connection Handling Error: " + exception);
        }

        // Try closing connection
        if (!clientSocket.isClosed()) {
            try {
                clientSocket.close();
            } catch (IOException exception) {
                System.out.println("[TCP Server] Connection Closing Error: " + exception);
            }
        }
    }

    protected abstract void handle(Socket clientSocket);
}
