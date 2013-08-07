package de.rub.nds.virtualnetworklayer.packet.header.internet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.Ethernet;
import de.rub.nds.virtualnetworklayer.packet.header.link.family.Family;
import de.rub.nds.virtualnetworklayer.packet.header.link.ppp.PPP;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.EnumSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * Internet Protocol Version 4
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Network)
public class Ip4Header extends Ip {
    public final static int Id = Headers.Ip4.getId();

    public static enum Flag {
        MBZ(0x01),
        DF(0x02),
        MF(0x04);

        private int position;

        private Flag(int position) {
            this.position = position;
        }
    }

    private Set<Flag> flags;

    @Override
    public int getLength() {
        return getSecondNibble(0) * 4;
    }

    public int getOptionsLength() {
        return 20 - getLength();
    }

    public int getTypeOfService() {
        return getUShort(1);
    }

    @Override
    public int getPayloadLength() {
        return getTotalLength() - getLength();
    }

    public int getTotalLength() {
        return getUShort(2);
    }

    public int getIdentification() {
        return getUShort(4);
    }

    public Set<Flag> getFlags() {
        if (flags == null) {
            flags = EnumSet.noneOf(Ip4Header.Flag.class);
            int mask = getFirstNibble(6) >> 1;

            for (Flag flag : Flag.values()) {
                if ((mask & flag.position) == flag.position) {
                    flags.add(flag);
                }
            }
        }

        return flags;
    }

    public int getFragmentOffset() {
        return (getUShort(6) & 0x3FFF) * 8;
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
        return getUShort(10);
    }

    @Override
    @Format(with = IpFormatter.class)
    public byte[] getSourceAddress() {
        return getBytes(12, 4);
    }

    @Override
    @Format(with = IpFormatter.class)
    public byte[] getDestinationAddress() {
        return getBytes(16, 4);
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isFragmented() {
        return getFlags().contains(Flag.MF);
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof Ethernet)) {
            Ethernet header = (Ethernet) previousHeaders.getLast();
            return header.getType() == Ethernet.Type.Ip4;
        }

        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof PPP)) {
            PPP header = (PPP) previousHeaders.getLast();
            return header.getProtocol() == PPP.Protocol.IP;
        }

        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof Family)) {
            Family header = (Family) previousHeaders.getLast();
            return header.getAddressFamily() == Family.AddressFamily.INET;
        }

        return dataLinkType == Pcap.DataLinkType.Raw && getVersion() == 4;
    }
}
