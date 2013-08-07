package de.rub.nds.virtualnetworklayer.packet.header.link;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.Ethernet;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Address Resolution Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class ArpHeader extends Header {
    public final static int Id = Headers.Arp.getId();

    public int getHardwareType() {
        return getUShort(0);
    }

    public Ethernet.Type getProtocolType() {
        return Ethernet.Type.valueOf(getUShort(2));
    }

    public int getHardwareAddressLength() {
        return getUByte(4);
    }

    public int getProtocolAddressLength() {
        return getUByte(5);
    }

    public int getOperation() {
        return getUShort(6);
    }

    @Format(with = MacFormatter.class)
    public byte[] getSenderHardwareAddress() {
        return getBytes(8, getHardwareAddressLength());
    }

    @Format(with = IpFormatter.class)
    public byte[] getSenderProtocolAddress() {
        return getBytes(14, getProtocolAddressLength());
    }

    @Format(with = MacFormatter.class)
    public byte[] getTargetHardwareAddress() {
        return getBytes(18, getHardwareAddressLength());
    }

    @Format(with = IpFormatter.class)
    public byte[] getTargetProtocolAddress() {
        return getBytes(24, getProtocolAddressLength());
    }

    @Override
    public int getLength() {
        return 28;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if ((previousHeaders.size() > 0) && (previousHeaders.getLast()) instanceof Ethernet) {
            Ethernet header = (Ethernet) previousHeaders.getLast();
            return header.getType() == Ethernet.Type.Arp;
        }

        return false;
    }
}
