package de.rub.nds.virtualnetworklayer.packet.header.link.family;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.ByteBuffer;
import java.util.LinkedList;

/**
 * BSD loopback encapsulation
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class NullHeader extends Header implements Family {
    public final static int Id = Headers.Null.getId();

    public AddressFamily getAddressFamily() {
        return AddressFamily.valueOf(getInteger(0));
    }

    @Override
    public int getLength() {
        return 4;
    }

    @Override
    public int getId() {
        return Id;
    }

    /**
     * Byte order is of the machine on which the packets are captured.
     * So try to find out.
     *
     * @return host byte ordered buffer
     */
    @Override
    protected ByteBuffer decode(ByteBuffer payload) {
        /*int family = payload.getInt(0);

        if (family > 0x01000000 || family < 0) {
            if (payload.order() == ByteOrder.LITTLE_ENDIAN) {
                return payload.order(ByteOrder.BIG_ENDIAN);
            } else {
                return payload.order(ByteOrder.LITTLE_ENDIAN);
            }
        }*/

        return payload;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.Null;
    }
}
