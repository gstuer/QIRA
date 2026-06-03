package com.gstuer.qira.enforcer.security;

import com.gstuer.qira.core.encapsulation.EncapsulationException;
import com.gstuer.qira.core.encapsulation.KeyedMessageEncapsulator;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.apache.commons.lang3.tuple.Pair;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
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
        // Step 1: Perform data encapsulation mechanism (DEM) lookup
        EthernetPacket.EthernetHeader packetHeader = (EthernetPacket.EthernetHeader) packet.getHeader();
        Collection<Pair<InetAddress, KeyedMessageEncapsulator<?, ?>>> encapsulators = this.keyLibrary.getTuplesDEM(packetHeader.getDstAddr());

        encapsulators.forEach(encapsulator -> {
            // Step 2: Encapsulate Ethernet frame into payload exchange message
            PayloadExchangeMessage payloadMessage = new PayloadExchangeMessage(encapsulator.getKey(), packet);
            try {
                // Step 3: Apply cryptographic encapsulation & add encapsulated message to
                this.messageEgress.add(encapsulator.getValue().encapsulate(payloadMessage));
            } catch (EncapsulationException exception) {
                System.out.println("[Security Controller | Outgoing] Encapsulation of payload exchange failed: " + exception);
            }
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
