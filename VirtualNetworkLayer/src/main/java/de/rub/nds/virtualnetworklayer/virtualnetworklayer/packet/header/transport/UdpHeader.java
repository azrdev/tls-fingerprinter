package de.rub.nds.virtualnetworklayer.packet.header.transport;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.IpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.util.List;

public class UdpHeader extends Header {

    public static int Id = 5;

    public int getSourcePort() {
        return getShort(0);
    }

    public int getDestinationPort() {
        return getShort(2);
    }

    @Override
    public int getPayloadLength() {
        return getShort(4);
    }

    public int getChecksum() {
        return getShort(6);
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
    public boolean isGreedy() {
        return true;
    }

    @Override
    public boolean isBound(List<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.get(previousHeaders.size() - 1) instanceof IpHeader) {
            IpHeader header = (IpHeader) previousHeaders.get(previousHeaders.size() - 1);

            return header.getNextHeader() == IpHeader.Protocol.Udp;
        }

        return false;
    }
}
