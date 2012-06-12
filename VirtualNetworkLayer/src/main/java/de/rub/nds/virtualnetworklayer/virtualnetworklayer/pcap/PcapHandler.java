package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_handler;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_pkthdr;
import org.bridj.Pointer;

import java.nio.ByteBuffer;

public abstract class PcapHandler extends pcap_handler {
    protected Pcap.DataLinkType dataLinkType;

    @Override
    public void callback(Pointer<?> user, Pointer<pcap_pkthdr> pkt_header, Pointer<?> pkt_data) {
        pcap_pkthdr header = pkt_header.get();
        long timeStamp = header.ts.getTime();
        int length = header.caplen;
        dataLinkType = Pcap.DataLinkType.valueOf(user.getInt());

        newHeader(timeStamp, length, pkt_data.getByteBuffer(length));
    }

    public abstract void newHeader(long timeStamp, int length, ByteBuffer byteBuffer);
}
