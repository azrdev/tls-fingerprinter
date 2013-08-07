package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Ethernet 2
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class EthernetHeader extends Header implements Ethernet {
    public final static int Id = Headers.Ethernet.getId();

    @Format(with = MacFormatter.class)
    public byte[] getDestinationMac() {
        return getBytes(0, 8);
    }

    @Format(with = MacFormatter.class)
    public byte[] getSourceMac() {
        return getBytes(8, 8);
    }

    @Override
    public Type getType() {
        return Type.valueOf(getUShort(12));
    }

    @Override
    public int getLength() {
        return 14;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty()
                && (dataLinkType == Pcap.DataLinkType.Ethernet) && getUShort(12) > 0x0600;
    }
}
