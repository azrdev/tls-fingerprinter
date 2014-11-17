package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_handler;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_pkthdr;
import org.bridj.Pointer;
import org.bridj.TimeT;

import java.nio.ByteBuffer;

/**
 * This is the abstract base callback that is passed to pcap.
 * It also holds the current {@link Pcap.DataLinkType}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class PcapHandler extends pcap_handler {
    protected Pcap.DataLinkType dataLinkType;

    private Pointer<pcap_pkthdr> current_pkt_hdr;
    private Pointer<Byte> current_bytes;

    @Override
    protected void callback(Pointer user, Pointer<pcap_pkthdr> pkt_header, Pointer<Byte> pkt_data) {
        pcap_pkthdr header = pkt_header.get();
        long timeStamp = header.getTimeStamp();
        int length = header.caplen();
        dataLinkType = Pcap.DataLinkType.valueOf(user.getInt());

        current_pkt_hdr = pkt_header;
        current_bytes = pkt_data;
        try {
            newByteBuffer(timeStamp, length, pkt_data.getByteBuffer(length));
        } finally {
            current_pkt_hdr = null;
            current_bytes = null;
        }
    }


    public Pcap.DataLinkType getDataLinkType() {
        return dataLinkType;
    }

    protected abstract void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer);

    /**
     *  raw pcap data - use with {@link PcapDumper#dump(org.bridj.Pointer,org.bridj.Pointer)}
     */
    public RawPacket getCurrentRawPacket() {
        return new RawPacket(current_pkt_hdr, current_bytes);
    }

    public static class RawPacket {
        private TimeT.timeval timeStamp;
        private int caplen;
        private int len;
        private ByteBuffer bytes;

        private RawPacket(Pointer<pcap_pkthdr> pkt_hdr, Pointer<Byte> bytes) {
            pcap_pkthdr header = pkt_hdr.get();
            timeStamp = header.ts();
            caplen = header.caplen();
            len = header.len();

            this.bytes = ByteBuffer.allocateDirect(caplen);
            this.bytes.put(bytes.getByteBuffer(caplen));
        }

        public Pointer<pcap_pkthdr> getHeaderNative() {
            pcap_pkthdr hdr = new pcap_pkthdr();

            hdr.ts(timeStamp);
            hdr.caplen(caplen);
            hdr.len(len);

            return Pointer.pointerTo(hdr);
        }

        public Pointer<Byte> getBytesNative() {
            return Pointer.pointerToBytes(bytes);
        }
    }
}
