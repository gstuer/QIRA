package com.gstuer.qira.core.message;

import org.pcap4j.packet.Packet;

import java.io.Serial;
import java.net.InetAddress;
import java.util.Objects;

public class PayloadExchangeMessage extends Message<Packet> {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    public PayloadExchangeMessage(InetAddress source, InetAddress destination, Packet packet) {
        super(source, destination, packet);
    }

    public PayloadExchangeMessage(InetAddress destination, Packet packet) {
        super(destination, packet);
    }

    @Override
    public PayloadExchangeMessage fromSource(InetAddress source) {
        return new PayloadExchangeMessage(source, this.getDestination(), this.getPayload());
    }

    @Override
    protected boolean hasEqualPayload(Message<?> message) {
        if (message == null || getClass() != message.getClass()) {
            return false;
        }
        PayloadExchangeMessage that = (PayloadExchangeMessage) message;
        return Objects.deepEquals(this.getPayload().getRawData(), that.getPayload().getRawData());
    }
}
