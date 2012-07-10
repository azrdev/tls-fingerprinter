package de.rub.nds.virtualnetworklayer.packet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.*;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ArpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.*;
import de.rub.nds.virtualnetworklayer.packet.header.link.family.NullHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.family.PfLogHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.ppp.PPPHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.ppp.PPPoEHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.wlan.IEEE802_11Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.wlan.PrismHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.wlan.RadiotapHeader;
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

/**
 * This class extends {@link PcapHandler} with packet parsing capabilities.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Header
 */
public abstract class PacketHandler extends PcapHandler {
    private static List<Header> headers = new LinkedList<Header>();
    private static Set<Header> greedyHeaders = new HashSet<Header>();
    private boolean deepCopy;

    static {
        registerHeader(new EthernetHeader());
        registerHeader(new IEEE802_2Header(), true);
        registerHeader(new IEEE802_3Header());
        registerHeader(new SnapHeader());
        registerHeader(new NullHeader());
        registerHeader(new PPPHeader());
        registerHeader(new SllHeader());
        registerHeader(new PfLogHeader());
        registerHeader(new RadiotapHeader());
        registerHeader(new PrismHeader());
        registerHeader(new IEEE802_11Header());
        registerHeader(new PPPoEHeader());
        registerHeader(new GreHeader());
        registerHeader(new IEEE802_1QHeader());
        registerHeader(new ArpHeader());
        registerHeader(new Ip4Header());
        registerHeader(new Ip6Header());
        registerHeader(new TcpHeader());
        registerHeader(new UdpHeader());
        registerHeader(new SmtpHeader());
        registerHeader(new HttpHeader(false));
        registerHeader(new SipHeader(false));
        registerHeader(new TlsHeader(false), true);
        registerHeader(new DhcpHeader());
    }

    /**
     * Convenience method with {@code greedy = false}.
     *
     * @param header
     * @see #registerHeader(Header, boolean)
     */
    public static void registerHeader(Header header) {
        registerHeader(header, false);
    }

    /**
     * Registers a new header.
     * </p>
     * Greedy headers swallow the complete payload,
     * so no header might follow.
     *
     * @param header
     * @param greedy
     */
    public static void registerHeader(Header header, boolean greedy) {
        headers.add(header);

        if (greedy) {
            greedyHeaders.add(header);
        }
    }

    public static int getHeaderCount() {
        return headers.size();
    }

    protected PacketHandler(boolean deepCopy) {
        this.deepCopy = deepCopy;
    }

    protected PacketHandler() {
        this(true);
    }

    private static Header getHeader(LinkedList<Header> packetHeaders, ByteBuffer byteBuffer, int offset, int limit, Pcap.DataLinkType dataLinkType) {
        byteBuffer.position(offset);
        ByteBuffer sliced = (ByteBuffer) byteBuffer.slice().limit(Math.min(byteBuffer.remaining(), limit));

        for (Header header : headers) {
            header.peer(sliced);

            if (header.isBound(packetHeaders, dataLinkType)) {
                return header;
            }
        }

        return null;
    }

    public static LinkedList<Header> getPacketHeaders(ByteBuffer byteBuffer) {
        return getPacketHeaders(byteBuffer, byteBuffer.capacity(), Pcap.DataLinkType.Ethernet, true);
    }

    public static LinkedList<Header> getPacketHeaders(ByteBuffer byteBuffer, int length, Pcap.DataLinkType dataLinkType) {
        return getPacketHeaders(byteBuffer, length, dataLinkType, false);
    }

    public static LinkedList<Header> getPacketHeaders(ByteBuffer byteBuffer, int length, Pcap.DataLinkType dataLinkType, boolean quirky) {
        LinkedList<Header> packetHeaders = new LinkedList<Header>();
        int offset = 0;
        int limit = byteBuffer.capacity();

        Header header;
        while (offset < length && (header = getHeader(packetHeaders, byteBuffer, offset, limit, dataLinkType)) != null) {
            Header packetHeader = header.clone();
            packetHeaders.add(packetHeader);

            offset += header.getLength();
            if (greedyHeaders.contains(header)) {
                offset += header.getPayloadLength();
            }

            if (!quirky && !greedyHeaders.contains(header)) {
                limit = Math.min(header.getPayloadLength(), length);
            }
        }

        return packetHeaders;
    }

    @Override
    protected final void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
        if (deepCopy) {
            byteBuffer = Util.clone(byteBuffer);
        }

        LinkedList<Header> packetHeaders = getPacketHeaders(byteBuffer, length, dataLinkType);

        newPacket(new PcapPacket(byteBuffer, timeStamp, packetHeaders));
    }

    protected abstract void newPacket(PcapPacket packet);

}
