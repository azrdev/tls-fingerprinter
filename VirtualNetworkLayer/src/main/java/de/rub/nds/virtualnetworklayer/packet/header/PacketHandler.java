package de.rub.nds.virtualnetworklayer.packet.header;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
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
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

public abstract class PacketHandler extends PcapHandler {

    private final static Logger logger = Logger.getLogger(PacketHandler.class.getName());

    private static List<Header> headers = new LinkedList<Header>();
    private static Set<Header> greedyHeaders = new HashSet<Header>();

    static {
        registerHeader(new EthernetHeader());
        registerHeader(new Ip4Header());
        registerHeader(new Ip6Header());
        registerHeader(new TcpHeader());
        registerHeader(new UdpHeader(), true);
        registerHeader(new TlsHeader(), true);
    }

    public static void registerHeader(Header header) {
        registerHeader(header, false);
    }

    public static void registerHeader(Header header, boolean greedy) {
        headers.add(header);

        if (greedy) {
            greedyHeaders.add(header);
        }
    }

    public static int getHeaderCount() {
        return headers.size();
    }

    private static Header getHeader(LinkedList<Header> packetHeaders, ByteBuffer byteBuffer, Pcap.DataLinkType dataLinkType) {
        for (Header header : headers) {
            header.peer(byteBuffer);

            if (header.isBound(packetHeaders, dataLinkType)) {
                return header;
            }
        }

        return null;
    }

    public static LinkedList<Header> getPacketHeaders(ByteBuffer byteBuffer) {
        return getPacketHeaders(byteBuffer, byteBuffer.capacity(), Pcap.DataLinkType.Ethernet);
    }

    public static LinkedList<Header> getPacketHeaders(ByteBuffer byteBuffer, int length, Pcap.DataLinkType dataLinkType) {
        LinkedList<Header> packetHeaders = new LinkedList<Header>();
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
            if (greedyHeaders.contains(header)) {
                offset += header.getPayloadLength();
            }

            if (offset < length) {
                byteBuffer.position(offset);
            }

        }

        return packetHeaders;
    }

    @Override
    public void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
        ByteBuffer deepCopy = Util.clone(byteBuffer);

        LinkedList<Header> packetHeaders = getPacketHeaders(deepCopy, length, dataLinkType);

        logger.info(packetHeaders.toString());
        newPacket(new PcapPacket(deepCopy, timeStamp, packetHeaders));
    }

    public abstract void newPacket(PcapPacket packet);

}
