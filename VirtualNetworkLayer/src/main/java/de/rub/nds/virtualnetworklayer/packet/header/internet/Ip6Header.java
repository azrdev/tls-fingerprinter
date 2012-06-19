package de.rub.nds.virtualnetworklayer.packet.header.internet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.EthernetHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.util.LinkedList;

public class Ip6Header extends IpHeader {
    public static int Id = 2;

    public int getTrafficClass() {
        return getUShort(0) & 0x0FFF;
    }

    public int getFlowLabel() {
        return getInteger(0) & 0x000FFFFF;
    }

    @Override
    public int getPayloadLength() {
        return getShort(4);
    }

    @Override
    public Protocol getNextHeader() {
        return Protocol.valueOf(getUByte(6));
    }

    public int getHopLimit() {
        return getUByte(7);
    }

    @Override
    public byte[] getSourceAddress() {
        return getBytes(8, 16);
    }

    @Override
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
            EthernetHeader header = (EthernetHeader) previousHeaders.getLast();
            return header.getType() == EthernetHeader.Type.Ip6;
        }

        return false;
    }
}
