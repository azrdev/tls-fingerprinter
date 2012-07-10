package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Generic Routing Encapsulation
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Network)
public class GreHeader extends Header implements Ethernet {
    public final static int Id = Headers.Gre.getId();

    public boolean isChecksumPresent() {
        return (getUByte(0) & 0x01) != 0;
    }

    public int getReserved0() {
        return (getUShort(0) & 0x3ffe) >> 1;
    }

    public int getVersion() {
        return getUShort(0) >> 13;
    }

    @Override
    public Type getType() {
        return Type.valueOf(getUShort(2));
    }

    public int getChecksum() {
        return getUShort(4);
    }

    public int getReserved1() {
        return getUShort(12);
    }

    @Override
    public int getLength() {
        return 8;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof Ip) {
            Ip header = (Ip) previousHeaders.getLast();

            return header.getNextHeader() == Ip.Protocol.Gre;
        }

        return false;
    }
}
