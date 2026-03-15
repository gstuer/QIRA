package com.gstuer.qira.enforcer;

import com.gstuer.qira.core.egress.DatagramEgressHandler;
import com.gstuer.qira.core.egress.FrameEgressHandler;
import com.gstuer.qira.core.ingress.DatagramIngressHandler;
import com.gstuer.qira.core.ingress.FrameIngressHandler;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.enforcer.predicate.PacketPredicate;
import com.gstuer.qira.enforcer.security.SecurityController;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

public class NetworkBridge {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;

    private final PcapNetworkInterface networkInterfaceInsecure;
    private final PcapNetworkInterface networkInterfaceSecure;

    private final BlockingQueue<Packet> egressQueueInsecure;
    private final BlockingQueue<Packet> egressQueueSecure;
    private final BlockingQueue<Message<?>> egressQueueMessage;

    private final PacketPredicate bypassPredicate;

    private FrameEgressHandler egressHandlerInsecure;
    private FrameEgressHandler egressHandlerSecure;
    private DatagramEgressHandler egressHandlerMessage;
    private FrameIngressHandler ingressHandlerInsecure;
    private FrameIngressHandler ingressHandlerSecure;
    private DatagramIngressHandler ingressHandlerMessage;

    private SecurityController securityController;
    private ExecutorService threadPool;

    public NetworkBridge(PcapNetworkInterface networkInterfaceInsecure, PcapNetworkInterface networkInterfaceSecure, PacketPredicate... bypassPredicates) {
        this.networkInterfaceInsecure = Objects.requireNonNull(networkInterfaceInsecure);
        this.networkInterfaceSecure = Objects.requireNonNull(networkInterfaceSecure);

        this.egressQueueInsecure = new LinkedBlockingQueue<>();
        this.egressQueueSecure = new LinkedBlockingQueue<>();
        this.egressQueueMessage = new LinkedBlockingQueue<>();

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
        this.egressQueueInsecure.clear();
        this.egressQueueSecure.clear();
        this.egressQueueMessage.clear();

        // Initialize security controller
        this.securityController = new SecurityController(this.egressQueueMessage, this.egressQueueSecure);

        // Specify ingress packet consumers
        Consumer<Packet> egressEnqueueInsecure = this.egressQueueInsecure::offer;
        Consumer<Packet> egressEnqueueSecure = this.egressQueueSecure::offer;
        Consumer<Packet> packetConsumerInsecure = (packet) -> bypassPredicate.doIfMatches(packet, egressEnqueueSecure);
        Consumer<Packet> packetConsumerSecure = (packet) -> bypassPredicate.doIfMatchesOrElse(packet,
                egressEnqueueInsecure, this.securityController::handleOutgoingRequest);

        // Construct ingress and egress handlers
        try {
            // Egress handler
            this.egressHandlerMessage = new DatagramEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, this.egressQueueMessage);
            this.egressHandlerInsecure = new FrameEgressHandler(this.networkInterfaceInsecure, this.egressQueueInsecure);
            this.egressHandlerSecure = new FrameEgressHandler(this.networkInterfaceSecure, this.egressQueueSecure);

            // Ingress handler
            this.ingressHandlerMessage = new DatagramIngressHandler(UDP_PORT_INCOMING, this.securityController::handleIncomingRequest);
            this.ingressHandlerInsecure = new FrameIngressHandler(this.networkInterfaceInsecure, packetConsumerInsecure);
            this.ingressHandlerSecure = new FrameIngressHandler(this.networkInterfaceSecure, packetConsumerSecure);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Start handler threads
        this.threadPool = Executors.newFixedThreadPool(6);
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
        this.threadPool.shutdownNow();
    }
}
