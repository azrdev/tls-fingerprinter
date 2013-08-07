package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * IEEE 802.2 (Llc)
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class IEEE802_2Header extends Header {
    public final static int Id = Headers.IEEE802_2.getId();

    public int getDestinationServiceAccessPoint() {
        return getUByte(0);
    }

    public int getSourceServiceAccessPoint() {
        return getUByte(1);
    }

    public int getControl() {
        if (getLength() == 3) {
            return getUByte(2);
        } else {
            return getUShort(2);
        }
    }

    @Override
    public int getLength() {
        return (getByte(2) & 0x3) == 0x3 ? 3 : 4;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.size() == 1 && previousHeaders.getLast() instanceof IEEE802_3Header;
    }
}
