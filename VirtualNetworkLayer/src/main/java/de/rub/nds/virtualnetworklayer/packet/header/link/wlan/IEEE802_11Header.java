package de.rub.nds.virtualnetworklayer.packet.header.link.wlan;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * IEEE 802.11 (WLan)
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class IEEE802_11Header extends Header {
    private final static int Id = Headers.IEEE802_11.getId();

    public int getProtocolVersion() {
        return getSecondNibble(0) & 0x03;
    }

    public int getType() {
        return (getSecondNibble(0) & 0x0c) >> 2;
    }

    public int getSubType() {
        return getFirstNibble(0);
    }

    public int getDuration() {
        return getUShort(1);
    }


    @Override
    public int getLength() {
        return 0;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof RadiotapHeader) {
            return dataLinkType == Pcap.DataLinkType.Radiotap;
        }

        return dataLinkType == Pcap.DataLinkType.IEEE802_11;
    }
}
