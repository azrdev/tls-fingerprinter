package de.rub.nds.virtualnetworklayer.packet.header.link.wlan;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * Radiotap
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see <a href="http://www.radiotap.org">radiotap.org</a>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class RadiotapHeader extends Header {
    private final static int Id = Headers.Radiotap.getId();

    public static enum Flag {
        TSFT(0x01),
        Flags(0x02),
        Rate(0x04),
        Channel(0x08),
        FHSS(0x10),
        dBmAntennaSignal(0x20),
        dBmAntennaNoise(0x40),
        LockQuality(0x80),
        TxAttenuation(0x100),
        dbTxAttenuation(0x200),
        dBmTxPower(0x400),
        Antenna(0x800),
        dbAntennaSignal(0x1000),
        dbAntennaNoise(0x2000),
        RxFlags(0x4000),
        TxFlags(0x8000),
        RtsRetries(0x10000),
        DataRetries(0x20000);

        private int position;

        private Flag(int position) {
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

    public Set<Flag> getPresent() {
        Set<Flag> flags = EnumSet.noneOf(Flag.class);
        long mask = getUInteger(4);

        for (Flag flag : Flag.values()) {
            if ((mask & flag.position) == flag.position) {
                flags.add(flag);
            }
        }

        return flags;
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
