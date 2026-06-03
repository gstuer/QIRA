package com.gstuer.qira.enforcer.security;

import com.gstuer.qira.core.cryptography.EncodedKey;
import com.gstuer.qira.core.handshake.HandshakeServer;
import com.gstuer.qira.core.serialization.JsonProcessor;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class KemHandshakeTest {
    private byte[] serverSecret;

    @Test
    public void testClientServerHandshake() throws Exception {
        // Start server
        HandshakeServer server = new HandshakeTestServer();
        Thread serverThread = new Thread(server::start);
        serverThread.start();

        Socket clientSocket = new Socket("127.0.0.1", 10005);
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        JsonProcessor jsonProcessor = new JsonProcessor();
        System.out.println("[Client] Wait for KEM public key.");
        EncodedKey encodedKey = jsonProcessor.convertToObject(in.readLine(), EncodedKey.class);
        PublicKey publicKey = KeyFactory.getInstance(encodedKey.getAlgorithmIdentifier()).generatePublic(new X509EncodedKeySpec(encodedKey.getKey()));
        System.out.println("[Client] Received KEM public key.");

        System.out.println("[Client] Encapsulate secret key.");
        KEM.Encapsulator keyEncapsulator = KEM.getInstance(encodedKey.getAlgorithmIdentifier()).newEncapsulator(publicKey);
        KEM.Encapsulated encapsulatedKey = keyEncapsulator.encapsulate();
        byte[] encapsulationMessage = encapsulatedKey.encapsulation();

        System.out.println("[Client] Send encapsulated secret key.");
        out.println(jsonProcessor.convertToJson(encapsulationMessage));

        System.out.println("[Client] Secret key: Hash=" + Arrays.hashCode(encapsulatedKey.key().getEncoded()) + " Bytes=" + encapsulatedKey.key().getEncoded().length);
        clientSocket.close();
        System.out.println("[Client] Closed: " + clientSocket.isClosed());
        server.stop();

        // Assumptions
        while (serverThread.isAlive()) {
            TimeUnit.MILLISECONDS.sleep(500);
        }
        assertArrayEquals(encapsulatedKey.key().getEncoded(), this.serverSecret);
    }

    private final class HandshakeTestServer extends HandshakeServer {
        public HandshakeTestServer() {
            super(10005);
        }

        @Override
        protected void handle(Socket clientSocket) {
            try {
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                JsonProcessor jsonProcessor = new JsonProcessor();
                System.out.println("[Server] Generate KEM keys.");
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM-1024");
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                System.out.println("[Server] Encode KEM public key.");
                KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-1024");
                X509EncodedKeySpec x509spec = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);

                System.out.println("[Server] Send KEM public key.");
                EncodedKey encodedKey = new EncodedKey("ML-KEM-1024", x509spec.getEncoded());
                out.println(jsonProcessor.convertToJson(encodedKey)); // TODO Authentication missing.

                System.out.println("[Server] Wait for KEM encapsulated key.");
                byte[] encapsulatedSecret = jsonProcessor.convertToObject(in.readLine(), byte[].class); // TODO Authentication of encapsulated key missing!
                System.out.println("[Server] Received key.");

                System.out.println("[Server] Decapsulate key.");
                KEM.Decapsulator keyDecapsulator = KEM.getInstance("ML-KEM-1024").newDecapsulator(keyPair.getPrivate());
                SecretKey secretKey = keyDecapsulator.decapsulate(encapsulatedSecret);
                System.out.println("[Server] Secret key: Hash=" + Arrays.hashCode(secretKey.getEncoded()) + " Bytes=" + secretKey.getEncoded().length);
                KemHandshakeTest.this.serverSecret = secretKey.getEncoded();
                clientSocket.close();
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        }
    }
}
