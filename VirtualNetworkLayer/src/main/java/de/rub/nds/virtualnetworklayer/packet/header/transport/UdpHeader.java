package de.rub.nds.virtualnetworklayer.packet.header.transport;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.Session;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * User Datagram Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Transport)
public class UdpHeader extends Header implements Session, Port {
    public static int Id = Headers.Udp.getId();

    public int getSourcePort() {
        return getUShort(0);
    }

    public int getDestinationPort() {
        return getUShort(2);
    }

    @Override
    public int getPayloadLength() {
        return getUShort(4);
    }

    public int getChecksum() {
        return getUShort(6);
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public int getLength() {
        return 8;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof Ip) {
            Ip header = (Ip) previousHeaders.getLast();

            return header.getNextHeader() == Ip.Protocol.Udp;
        }

        return false;
    }

    @Override
    public SocketSession getSession(PcapPacket packet) {
        Ip ipHeader = (Ip) (packet.hasHeader(Ip4Header.Id) ? packet.getHeader(Ip4Header.Id) : packet.getHeader(Ip6Header.Id));

        return new SocketSession(ipHeader.getSourceAddress(), ipHeader.getDestinationAddress(),
                getSourcePort(), getDestinationPort());
    }
}
