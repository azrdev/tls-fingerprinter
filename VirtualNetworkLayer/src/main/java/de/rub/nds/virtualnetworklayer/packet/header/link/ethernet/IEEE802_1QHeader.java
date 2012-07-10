package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * IEEE 802.1Q (VLan)
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class IEEE802_1QHeader extends Header implements Ethernet {
    public final static int Id = Headers.IEEE802_1Q.getId();

    public int getPriorityCodePoint() {
        return getUShort(0) >> 5;
    }

    public int getCanonicalFormatIndicator() {
        return getFirstNibble(2) & 1;
    }

    public int getVLanIdentifier() {
        return getUShort(2) & 0x0fff;
    }

    @Override
    public Type getType() {
        return Type.valueOf(getUShort(2));
    }

    @Override
    public int getLength() {
        return 4;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof Ethernet) {
            Ethernet header = (Ethernet) previousHeaders.getLast();
            return header.getType() == Type.IEEE802_1Q;
        }

        return false;
    }
}
