package de.rub.nds.virtualnetworklayer.packet.header.internet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.Ethernet;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.EthernetHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.family.Family;
import de.rub.nds.virtualnetworklayer.packet.header.link.ppp.PPP;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Internet Protocol Version 6
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Network)
public class Ip6Header extends Ip {
    public final static int Id = Headers.Ip6.getId();

    public int getTrafficClass() {
        return getUShort(0) & 0x0FFF;
    }

    public int getFlowLabel() {
        return getInteger(0) & 0x000FFFFF;
    }

    @Override
    public int getPayloadLength() {
        return getUShort(4);
    }

    @Override
    public Protocol getNextHeader() {
        return Protocol.valueOf(getUByte(6));
    }

    public int getHopLimit() {
        return getUByte(7);
    }

    @Override
    @Format(with = IpFormatter.class)
    public byte[] getSourceAddress() {
        return getBytes(8, 16);
    }

    @Override
    @Format(with = IpFormatter.class)
    public byte[] getDestinationAddress() {
        return getBytes(24, 16);
    }

    @Override
    public int getLength() {
        return 40;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof EthernetHeader) {
            Ethernet header = (Ethernet) previousHeaders.getLast();
            return header.getType() == Ethernet.Type.Ip6;
        }

        if (previousHeaders.getLast() instanceof PPP) {
            PPP header = (PPP) previousHeaders.getLast();
            return header.getProtocol() == PPP.Protocol.IPv6;
        }

        if (previousHeaders.getLast() instanceof Family) {
            Family header = (Family) previousHeaders.getLast();
            return header.getAddressFamily().isINet6();
        }

        return dataLinkType == Pcap.DataLinkType.Raw && getVersion() == 6;
    }
}
