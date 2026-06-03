package com.gstuer.qira.enforcer.security;

import com.gstuer.qira.core.encapsulation.EncapsulationException;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.handshake.HandshakeException;
import com.gstuer.qira.core.identity.IdentityBinding;
import com.gstuer.qira.core.identity.query.GuardedQuery;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

public class SecurityController {
    private final KeyLibrary keyLibrary;
    private final BlockingQueue<Message<?>> messageEgress;
    private final BlockingQueue<Packet> packetEgress;

    public SecurityController(KeyLibrary keyLibrary, BlockingQueue<Message<?>> messageEgress, BlockingQueue<Packet> packetEgress) {
        this.keyLibrary = Objects.requireNonNull(keyLibrary);
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.packetEgress = Objects.requireNonNull(packetEgress);
    }

    public void handleOutgoingRequest(Packet packet) {
        // Step 1: Perform enforcer binding lookup
        IdentityBinding ownBinding = this.keyLibrary.getOwnBinding();
        EthernetPacket.EthernetHeader packetHeader = (EthernetPacket.EthernetHeader) packet.getHeader();
        GuardedQuery identityQuery = new GuardedQuery(packetHeader.getDstAddr());
        Set<IdentityBinding> bindings;
        try {
            bindings = this.keyLibrary.resolveIdentity(identityQuery);
        } catch (HandshakeException exception) {
            System.out.println("[Security Controller | Outgoing] Lookup of enforcer identity failed: " + exception);
            return;
        }

        // Step 2: Perform data encapsulation mechanism (DEM) lookup
        bindings.parallelStream().forEach(binding -> {
            Optional<KeyedMessageEncapsulator<?, ?>> optionalEncapsulator = this.keyLibrary.getMessageEncapsulator(binding);
            optionalEncapsulator.ifPresent(encapsulator -> {
                // Step 3: Encapsulate Ethernet frame into payload exchange message
                PayloadExchangeMessage payloadMessage = new PayloadExchangeMessage(ownBinding.getEnforcerIdentity(),
                        binding.getEnforcerIdentity(), packet);
                try {
                    // Step 4: Apply cryptographic encapsulation & add encapsulated message to
                    this.messageEgress.add(encapsulator.encapsulate(payloadMessage));
                } catch (EncapsulationException exception) {
                    System.out.println("[Security Controller | Outgoing] Encapsulation of payload exchange failed: " + exception);
                }
            });
        });
    }

    public void handleIncomingRequest(Message<?> incomingMessage) {
        // Step 1: Perform data encapsulation mechanism (DEM) lookup
        Optional<KeyedMessageEncapsulator<?, ?>> optionalDecapsulator = this.keyLibrary.getMessageDecapsulator(incomingMessage.getSource());
        if (optionalDecapsulator.isPresent()) {
            KeyedMessageEncapsulator<?, ?> decapsulator = optionalDecapsulator.get();

            // Step 2: Decapsulate message
            Message<?> innerMessage;
            try {
                innerMessage = decapsulator.decapsulate(incomingMessage);
            } catch (EncapsulationException exception) {
                System.out.println("[Security Controller | Incoming] Decapsulation of message failed: " + exception);
                return;
            }

            // Step 3: Check message type & cast message
            if (innerMessage instanceof PayloadExchangeMessage payloadMessage) {
                // Step 4: Queue encapsulated Ethernet frame for secure raw egress
                this.packetEgress.offer(payloadMessage.getPayload());
            } else {
                System.out.println("[Security Controller | Incoming] Unsupported nested message type: " + innerMessage.getClass().getCanonicalName());
            }
        } else {
            System.out.println("[Security Controller | Incoming] No decapsulator available for message from " + incomingMessage.getSource() + ".");
        }
    }
}
