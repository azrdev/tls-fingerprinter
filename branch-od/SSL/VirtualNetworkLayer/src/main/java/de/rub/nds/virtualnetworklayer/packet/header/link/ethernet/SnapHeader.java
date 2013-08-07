package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Subnetwork Access Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class SnapHeader extends Header implements Ethernet {
    public final static int Id = Headers.Snap.getId();

    public long getOrganizationallyUniqueIdentifier() {
        return getUInteger(0) & 0x00FFFFFF;
    }

    @Override
    public Type getType() {
        if (getOrganizationallyUniqueIdentifier() == 0) {
            return Type.valueOf(getUShort(3));
        }

        return null;
    }

    @Override
    public int getLength() {
        return 5;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.size() > 0 && previousHeaders.getLast() instanceof IEEE802_2Header) {
            IEEE802_2Header header = (IEEE802_2Header) previousHeaders.getLast();

            return header.getDestinationServiceAccessPoint() == 0xaa;
        }

        return false;
    }
}
