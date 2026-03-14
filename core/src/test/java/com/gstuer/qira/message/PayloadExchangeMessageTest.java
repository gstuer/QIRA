package com.gstuer.qira.message;

import com.gstuer.qira.core.message.PayloadExchangeMessage;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

public class PayloadExchangeMessageTest extends MessageTest<PayloadExchangeMessage> {
    @Override
    protected PayloadExchangeMessage constructMessage() throws Throwable {
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Packet packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();
        return new PayloadExchangeMessage(source, destination, packet);
    }
}
