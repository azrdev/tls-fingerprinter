package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;


import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * IEEE 802.3
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class IEEE802_3Header extends Header {
    public final static int Id = Headers.IEEE802_3.getId();

    @Format(with = MacFormatter.class)
    public byte[] getDestinationMac() {
        return getBytes(0, 6);
    }

    @Format(with = MacFormatter.class)
    public byte[] getSourceMac() {
        return getBytes(6, 6);
    }

    @Override
    public int getPayloadLength() {
        return getUShort(12);
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
                && (dataLinkType == Pcap.DataLinkType.Ethernet) && getUShort(12) < 0x0600;
    }
}
