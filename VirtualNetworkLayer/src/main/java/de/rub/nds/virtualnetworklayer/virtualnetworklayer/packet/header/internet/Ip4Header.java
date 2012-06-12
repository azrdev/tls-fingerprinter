package de.rub.nds.virtualnetworklayer.packet.header.internet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.EthernetHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public class Ip4Header extends IpHeader {
    public static int Id = 2;

    public static enum Flag {
        MBZ(0x01),
        DF(0x02),
        MF(0x04);

        private int position;

        private Flag(int position) {
            this.position = position;
        }
    }

    @Override
    public int getLength() {
        return getSecondNibble(0) * 4;
    }

    public int getOptionsLength() {
        return 20 - getLength();
    }

    public int getTypeOfService() {
        return getShort(1);
    }

    public int getTotalLength() {
        return getShort(2);
    }

    public int getIdentification() {
        return getShort(4);
    }

    public Set<Flag> getFlags() {
        Set<Flag> flags = EnumSet.noneOf(Ip4Header.Flag.class);
        int mask = getFirstNibble(6) >> 1;

        for (Flag flag : Flag.values()) {
            if ((mask & flag.position) == flag.position) {
                flags.add(flag);
            }
        }

        return flags;
    }

    public int getFragmentOffset() {
        return getShort(6) & 0x3FFF;
    }

    public int getTimeToLive() {
        return getUByte(8);
    }

    @Override
    public int getHopLimit() {
        return getTimeToLive();
    }

    public Protocol getProtocol() {
        return getNextHeader();
    }

    @Override
    public Protocol getNextHeader() {
        return Protocol.valueOf(getByte(9));
    }


    public int getHeaderChecksum() {
        return getShort(10);
    }

    @Override
    public byte[] getSourceAddress() {
        return getBytes(12, 4);
    }

    @Override
    public byte[] getDestinationAddress() {
        return getBytes(16, 4);
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(List<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {

        if (previousHeaders.get(previousHeaders.size() - 1) instanceof EthernetHeader) {
            EthernetHeader header = (EthernetHeader) previousHeaders.get(previousHeaders.size() - 1);
            return header.getType() == EthernetHeader.Type.Ip4;
        }

        return false;
    }
}
