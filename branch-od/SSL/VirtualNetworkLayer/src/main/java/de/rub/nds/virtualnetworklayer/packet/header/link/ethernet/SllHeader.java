package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Linux cooked-mode capture
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class SllHeader extends Header implements Ethernet {
    public final static int Id = Headers.Sll.getId();

    public static enum HardwareAddressType {
        Host,
        Broadcast,
        Multicast,
        OtherHost,
        Outgoing
    }

    public int getPacketType() {
        return getUShort(0);
    }

    public HardwareAddressType getHardwareAddressType() {
        return HardwareAddressType.values()[getUShort(2)];
    }

    public int getLinkLayerAddressLength() {
        return getUShort(4);
    }

    @Format(with = MacFormatter.class)
    public byte[] getAddress() {
        return getBytes(6, getLinkLayerAddressLength());
    }

    public Type getType() {
        return Type.valueOf(getUShort(14));
    }

    @Override
    public int getLength() {
        return 16;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.Sll;
    }
}
