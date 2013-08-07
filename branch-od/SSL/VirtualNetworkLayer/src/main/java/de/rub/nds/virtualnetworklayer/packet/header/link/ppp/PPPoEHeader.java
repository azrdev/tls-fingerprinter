package de.rub.nds.virtualnetworklayer.packet.header.link.ppp;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.Ethernet;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Point-to-point Protocol over Ethernet
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class PPPoEHeader extends Header implements PPP {
    public final static int Id = Headers.PPPoE.getId();

    public int getVersion() {
        return getFirstNibble(0);
    }

    public int getType() {
        return getSecondNibble(0);
    }

    public int getCode() {
        return getUByte(1);
    }

    public int getSessionId() {
        return getUShort(2);
    }

    @Override
    public int getPayloadLength() {
        return getUShort(4);
    }

    @Override
    public Protocol getProtocol() {
        return Protocol.valueOf(getUShort(6));
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
        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof Ethernet)) {
            Ethernet header = (Ethernet) previousHeaders.getLast();
            return (header.getType() == Ethernet.Type.PPPoE_Session ||
                    header.getType() == Ethernet.Type.PPPoE_Discovery);
        }

        return dataLinkType == Pcap.DataLinkType.PPPoE;
    }
}
