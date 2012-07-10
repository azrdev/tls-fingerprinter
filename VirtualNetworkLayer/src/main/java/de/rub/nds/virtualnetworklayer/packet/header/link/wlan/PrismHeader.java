package de.rub.nds.virtualnetworklayer.packet.header.link.wlan;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;

/**
 * Prism
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see <a href="http://home.martin.cc/linux/prism">home.martin.cc/linux/prism/a>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class PrismHeader extends Header {
    private final static int Id = Headers.Prism.getId();

    public long getMessageCode() {
        return getUInteger(0);
    }

    @Override
    public int getLength() {
        return (int) getUInteger(4);
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.Prism;
    }
}
