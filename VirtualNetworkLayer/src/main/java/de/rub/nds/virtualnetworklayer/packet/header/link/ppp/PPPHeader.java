package de.rub.nds.virtualnetworklayer.packet.header.link.ppp;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Point-to-point Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class PPPHeader extends Header implements PPP {
    public final static int Id = Headers.PPP.getId();

    public int getFlags() {
        return getUByte(0);
    }

    public int getAddress() {
        return getUByte(1);
    }

    public int getControl() {
        return getUByte(2);
    }

    @Override
    public Protocol getProtocol() {
        return Protocol.valueOf(getUShort(3));
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
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.PPP;
    }
}
