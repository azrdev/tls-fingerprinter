package de.rub.nds.virtualnetworklayer.packet.header.link.wlan;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Radiotap
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see <a href="http://www.radiotap.org">radiotap.org</a>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class RadiotapHeader extends Header {
    private final static int Id = Headers.Radiotap.getId();

    public static enum Type {
        TSFT(0),
        Flags(1),
        Rate(2),
        Channel(3),
        FHSS(4),
        dBmAntennaSignal(5),
        dBmAntennaNoise(6),
        LockQuality(7),
        TxAttenuation(8),
        dbTxAttenuation(9),
        dBmTxPower(10),
        Antenna(11),
        dbAntennaSignal(12),
        dbAntennaNoise(13),
        RxFlags(14),
        TxFlags(15),
        RtsRetries(16),
        DataRetries(17),
        Ext(31);

        private int position;

        private Type(int position) {
            this.position = position;
        }
    }

    public int getVersion() {
        return getUByte(0);
    }

    public int getPadding() {
        return getUByte(1);
    }

    @Override
    public int getLength() {
        return getUShort(2);
    }

    public long getPresent() {
        return getUInteger(4);
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    protected ByteBuffer decode(ByteBuffer payload) {
        return payload.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.Radiotap;
    }
}
