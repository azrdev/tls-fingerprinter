package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_handler;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_pkthdr;
import org.bridj.Pointer;

import java.nio.ByteBuffer;

/**
 * This is the abstract base callback that is passed to pcap.
 * It also holds the current {@link Pcap.DataLinkType}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class PcapHandler extends pcap_handler {
    protected Pcap.DataLinkType dataLinkType;

    // raw pcap data - use these with {@link PcapDumper#dump(org.bridj.Pointer,org.bridj.Pointer)}
    protected Pointer<pcap_pkthdr> current_pkt_hdr;
    protected Pointer<Byte> current_bytes;

    @Override
    protected void callback(Pointer user, Pointer<pcap_pkthdr> pkt_header, Pointer<Byte> pkt_data) {
        pcap_pkthdr header = pkt_header.get();
        long timeStamp = header.getTimeStamp();
        int length = header.caplen();
        dataLinkType = Pcap.DataLinkType.valueOf(user.getInt());

        current_pkt_hdr = pkt_header;
        current_bytes = pkt_data;
        newByteBuffer(timeStamp, length, pkt_data.getByteBuffer(length));
        current_pkt_hdr = null;
        current_bytes = null;
    }


    public Pcap.DataLinkType getDataLinkType() {
        return dataLinkType;
    }

    protected abstract void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer);
}
