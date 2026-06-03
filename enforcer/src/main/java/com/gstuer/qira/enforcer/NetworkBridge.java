package com.gstuer.qira.enforcer;

import com.gstuer.qira.core.cryptography.signature.Verifier;
import com.gstuer.qira.core.egress.DatagramEgressHandler;
import com.gstuer.qira.core.egress.FrameEgressHandler;
import com.gstuer.qira.core.handshake.HandshakeException;
import com.gstuer.qira.core.ingress.DatagramIngressHandler;
import com.gstuer.qira.core.ingress.FrameIngressHandler;
import com.gstuer.qira.core.message.BindingRegistrationResponse;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.enforcer.predicate.PacketPredicate;
import com.gstuer.qira.enforcer.security.KeyLibrary;
import com.gstuer.qira.enforcer.security.SecurityController;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

public class NetworkBridge {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;
    private static final int TCP_PORT_AUTHORITY = 10010;

    private final KeyLibrary keyLibrary;

    private final PcapNetworkInterface networkInterfaceInsecure;
    private final PcapNetworkInterface networkInterfaceSecure;

    private final BlockingQueue<Packet> egressQueueInsecureRaw;
    private final BlockingQueue<Packet> egressQueueSecureRaw;
    private final BlockingQueue<Message<?>> egressQueueInsecureMessage;

    private final PacketPredicate bypassPredicate;

    private FrameEgressHandler egressHandlerInsecure;
    private FrameEgressHandler egressHandlerSecure;
    private DatagramEgressHandler egressHandlerMessage;
    private FrameIngressHandler ingressHandlerInsecure;
    private FrameIngressHandler ingressHandlerSecure;
    private DatagramIngressHandler ingressHandlerMessage;

    private SecurityController securityController;
    private ExecutorService threadPool;

    public NetworkBridge(PcapNetworkInterface networkInterfaceInsecure, PcapNetworkInterface networkInterfaceSecure,
                         MacAddress guardedEntity, InetAddress identityAuthorityAddress,
                         Verifier<?> identityAuthorityVerifier, PacketPredicate... bypassPredicates) {
        InetAddress insecureNetworkAddress = networkInterfaceInsecure.getAddresses().getFirst().getAddress();
        this.keyLibrary = new KeyLibrary(insecureNetworkAddress, Objects.requireNonNull(guardedEntity),
                Objects.requireNonNull(identityAuthorityAddress), TCP_PORT_AUTHORITY,Objects.requireNonNull(identityAuthorityVerifier));

        this.networkInterfaceInsecure = Objects.requireNonNull(networkInterfaceInsecure);
        this.networkInterfaceSecure = Objects.requireNonNull(networkInterfaceSecure);

        this.egressQueueInsecureRaw = new LinkedBlockingQueue<>();
        this.egressQueueSecureRaw = new LinkedBlockingQueue<>();
        this.egressQueueInsecureMessage = new LinkedBlockingQueue<>();

        // Compose predicates for traffic bypass to single predicate
        PacketPredicate composedPredicate = PacketPredicate.getStaticPredicate(false);
        for (PacketPredicate bypassPredicate : bypassPredicates) {
            composedPredicate = composedPredicate.or(bypassPredicate);
        }
        this.bypassPredicate = composedPredicate;
    }

    public void open() {
        // If bridge is already open, ignore method call
        if ((this.egressHandlerInsecure != null || this.egressHandlerSecure != null
                || this.ingressHandlerInsecure != null || this.ingressHandlerSecure != null)
                && !this.threadPool.isTerminated()) {
            return;
        }

        // Clear egress queues of previously opened bridge
        this.egressQueueInsecureRaw.clear();
        this.egressQueueSecureRaw.clear();
        this.egressQueueInsecureMessage.clear();

        // Register identity at identity authority
        try {
            BindingRegistrationResponse.ResponseType response = this.keyLibrary.registerIdentity();
            if (response == BindingRegistrationResponse.ResponseType.FAILED) {
                throw new HandshakeException("Identity registration at identity authority failed.");
            }
        } catch (HandshakeException exception) {
            throw new IllegalStateException(exception);
        }

        // Initialize security controller
        this.securityController = new SecurityController(this.keyLibrary, this.egressQueueInsecureMessage, this.egressQueueSecureRaw);

        // Specify ingress packet consumers
        Consumer<Packet> egressEnqueueInsecure = this.egressQueueInsecureRaw::offer;
        Consumer<Packet> egressEnqueueSecure = this.egressQueueSecureRaw::offer;
        Consumer<Packet> packetConsumerInsecure = (packet) -> bypassPredicate.doIfMatches(packet, egressEnqueueSecure);
        Consumer<Packet> packetConsumerSecure = (packet) -> bypassPredicate.doIfMatchesOrElse(packet,
                egressEnqueueInsecure, this.securityController::handleOutgoingRequest);

        // Construct ingress and egress handlers
        try {
            InetAddress insecureNetworkAddress = networkInterfaceInsecure.getAddresses().getFirst().getAddress();

            // Egress handler
            this.egressHandlerMessage = new DatagramEgressHandler(insecureNetworkAddress, UDP_PORT_OUTGOING, UDP_PORT_INCOMING, this.egressQueueInsecureMessage);
            this.egressHandlerInsecure = new FrameEgressHandler(this.networkInterfaceInsecure, this.egressQueueInsecureRaw);
            this.egressHandlerSecure = new FrameEgressHandler(this.networkInterfaceSecure, this.egressQueueSecureRaw);

            // Ingress handler
            this.ingressHandlerMessage = new DatagramIngressHandler(insecureNetworkAddress, UDP_PORT_INCOMING, this.securityController::handleIncomingRequest);
            this.ingressHandlerInsecure = new FrameIngressHandler(this.networkInterfaceInsecure, packetConsumerInsecure);
            this.ingressHandlerSecure = new FrameIngressHandler(this.networkInterfaceSecure, packetConsumerSecure);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Start handler threads
        this.threadPool = Executors.newFixedThreadPool(7);
        this.threadPool.submit(this.keyLibrary::startKeyExchangeServer);
        this.threadPool.submit(this.egressHandlerMessage::open);
        this.threadPool.submit(this.egressHandlerInsecure::open);
        this.threadPool.submit(this.egressHandlerSecure::open);
        this.threadPool.submit(this.ingressHandlerMessage::open);
        this.threadPool.submit(this.ingressHandlerInsecure::open);
        this.threadPool.submit(this.ingressHandlerSecure::open);
    }

    public void close() {
        this.ingressHandlerInsecure.close();
        this.ingressHandlerSecure.close();
        this.ingressHandlerMessage.close();
        this.egressHandlerInsecure.close();
        this.egressHandlerSecure.close();
        this.egressHandlerMessage.close();
        try {
            this.keyLibrary.stopKeyExchangeServer();
        } catch (IOException exception) {
            System.out.println("[Network Bridge] Stopping key exchange server failed: " + exception);
        }
        this.threadPool.shutdownNow();
    }
}
