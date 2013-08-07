package de.rub.nds.virtualnetworklayer.packet.header.link.family;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * OpenBSD pflog
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class PfLogHeader extends Header implements Family {
    public final static int Id = Headers.PfLog.getId();

    public enum Reason {
        Match,
        BadOffset,
        Fragment,
        Short,
        Normalize,
        Memory,
    }

    public enum Action {
        Pass,
        Drop,
        Scrub,
    }

    @Override
    public int getLength() {
        return getUByte(0);
    }

    @Override
    public AddressFamily getAddressFamily() {
        return AddressFamily.valueOf(getUShort(0));
    }

    public Action getAction() {
        return Action.values()[getUShort(24)];
    }

    public Reason getReason() {
        return Reason.values()[getUShort(22)];
    }

    public String getInterfaceName() {
        return new String(getBytes(4, 16));
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.PfLog;
    }
}
