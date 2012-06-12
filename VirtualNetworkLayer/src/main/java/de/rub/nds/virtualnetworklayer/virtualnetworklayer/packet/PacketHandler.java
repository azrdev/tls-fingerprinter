package de.rub.nds.virtualnetworklayer.packet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.EthernetHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.UdpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.pcap.PcapHandler;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public abstract class PacketHandler extends PcapHandler {

    private static List<Header> headers = new LinkedList<Header>();

    static {
        headers.add(new EthernetHeader());
        headers.add(new Ip4Header());
        headers.add(new Ip6Header());
        headers.add(new TcpHeader());
        headers.add(new UdpHeader());
        headers.add(new TlsHeader());
    }

    public static void registerHeader(Header header) {
        headers.add(header);
    }

    public static int getRegisteredHeaderCount() {
        return headers.size();
    }

    private static Header getHeader(List<Header> packetHeaders, ByteBuffer byteBuffer, Pcap.DataLinkType dataLinkType) {
        for (Header header : headers) {
            header.peer(byteBuffer);

            if (header.isBound(packetHeaders, dataLinkType)) {
                return header;
            }
        }

        return null;
    }

    public static List<Header> getPacketHeaders(ByteBuffer byteBuffer, int length) {
        return getPacketHeaders(byteBuffer, length, Pcap.DataLinkType.Ethernet);
    }

    public static List<Header> getPacketHeaders(ByteBuffer byteBuffer, int length, Pcap.DataLinkType dataLinkType) {
        List<Header> packetHeaders = new ArrayList<Header>();
        int offset = 0;

        Header header;
        while (offset < length && (header = getHeader(packetHeaders, byteBuffer.slice(), dataLinkType)) != null) {
            Header previousHeader = null;
            if (packetHeaders.size() > 0) {
                previousHeader = packetHeaders.get(packetHeaders.size() - 1);
            }
            Header packetHeader = header.clone(previousHeader, offset);
            packetHeaders.add(packetHeader);

            offset += header.getLength();
            if (header.isGreedy()) {
                offset += header.getPayloadLength();
            }

            if (offset < length) {
                byteBuffer.position(offset);
            }

        }

        return packetHeaders;
    }

    @Override
    public void newHeader(long timeStamp, int length, ByteBuffer byteBuffer) {
        ByteBuffer deepCopy = Util.clone(byteBuffer);

        List<Header> packetHeaders = getPacketHeaders(deepCopy, length, dataLinkType);
        newPacket(new PcapPacket(deepCopy, timeStamp, packetHeaders));
    }

    public abstract void newPacket(PcapPacket packet);

}
