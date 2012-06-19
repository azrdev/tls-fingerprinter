package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.EthernetHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.UdpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.junit.Test;

import java.io.File;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;

import static junit.framework.Assert.*;

public class PacketHandlerTest {
    private static String path = PacketHandlerTest.class.getResource("").getPath();

    public class CountingPacketHandler extends PacketHandler {
        private int[] headerCount;
        private int fragmentCount = 0;

        public CountingPacketHandler() {
            headerCount = new int[getHeaderCount() + 1];
        }

        @Override
        public void newPacket(PcapPacket packet) {
            for (Header header : packet.getHeaders()) {
                increaseHeaderCount(header.getId());
                if (header.isFragmented()) {
                    fragmentCount++;
                }
            }
        }

        private void increaseHeaderCount(int headerId) {
            headerCount[headerId] = ++headerCount[headerId];
        }

        public int getHeaderCount(int headerId) {
            return headerCount[headerId];
        }

        public int getFragmentCount() {
            return fragmentCount;
        }
    }

    public class QueueingPacketHandler extends PacketHandler {
        private Queue<PcapPacket> packets = new ArrayBlockingQueue<PcapPacket>(10);

        @Override
        public void newPacket(PcapPacket packet) {
            packets.add(packet);
        }

        public Queue<PcapPacket> getPackets() {
            return packets;
        }
    }

    @Test
    public void httpsGoogle() {
        File file = new File(path, "httpsGoogle.pcap");
        Pcap pcap = Pcap.openOffline(file);

        CountingPacketHandler packetHandler = new CountingPacketHandler();
        pcap.loop(packetHandler);

        assertEquals(122, packetHandler.getHeaderCount(TcpHeader.Id));
        assertEquals(134, packetHandler.getHeaderCount(Ip4Header.Id));
        assertEquals(137, packetHandler.getHeaderCount(EthernetHeader.Id));
        assertEquals(15, packetHandler.getHeaderCount(UdpHeader.Id));
        assertEquals(3, packetHandler.getHeaderCount(Ip6Header.Id));

        assertEquals(7, packetHandler.getFragmentCount());
        assertEquals(59, packetHandler.getHeaderCount(TlsHeader.Id));
    }

    @Test
    public void serverHelloTlsFragmented() {
        File file = new File(path, "serverHelloTlsFragmented.pcap");
        Pcap pcap = Pcap.openOffline(file);

        QueueingPacketHandler packetHandler = new QueueingPacketHandler();
        pcap.loop(packetHandler);

        Queue<PcapPacket> packets = packetHandler.getPackets();
        assertEquals(2, packets.size());
        assertTrue(packets.peek().hasHeader(TlsHeader.Id));
        assertEquals(92, packets.peek().getHeader(TlsHeader.Id).getPayloadLength());
        assertEquals(5, packets.peek().getHeaders().size());

        assertFalse(packets.peek().getHeader(TlsHeader.Id).isFragmented());
        assertTrue(packets.peek().getHeader(TlsHeader.Id, 1).isFragmented());
        packets.remove();
        assertFalse(packets.peek().hasHeader(TlsHeader.Id));
        assertEquals(3, packets.peek().getHeaders().size());
    }

    @Test
    public void clientHelloTls() {
        File file = new File(path, "clientHelloTls.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                EthernetHeader ethernetHeader = packet.getHeader(EthernetHeader.Id);
                assertEquals(EthernetHeader.Type.Ip4, ethernetHeader.getType());

                Ip4Header ip4Header = packet.getHeader(Ip4Header.Id);
                assertEquals(232, ip4Header.getTotalLength());
                assertEquals(20, ip4Header.getLength());
                assertEquals(0, ip4Header.getFragmentOffset());
                assertEquals(0, ip4Header.getTypeOfService());
                assertEquals(128, ip4Header.getTimeToLive());
                assertEquals(Ip4Header.Protocol.Tcp, ip4Header.getProtocol());
                assertEquals(591, ip4Header.getIdentification());
                assertTrue(ip4Header.getFlags().contains(Ip4Header.Flag.DF));
                assertEquals(1, ip4Header.getFlags().size());
                assertEquals(0, ip4Header.getHeaderChecksum());
                assertEquals("192.168.1.58", Util.toIp4String(ip4Header.getSourceAddress()));
                assertEquals("74.125.79.95", Util.toIp4String(ip4Header.getDestinationAddress()));

                TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
                assertEquals(49185, tcpHeader.getSourcePort());
                assertEquals(443, tcpHeader.getDestinationPort());

                assertEquals(3395842216L, tcpHeader.getSequenceNumber());
                assertEquals(230804170, tcpHeader.getAcknowledgmentNumber());

                assertEquals(16695, tcpHeader.getWindowSize());
                assertEquals(0x5c99, tcpHeader.getChecksum());
                assertEquals(0, tcpHeader.getReserved());

                Set<TcpHeader.Flag> flags = tcpHeader.getFlags();
                assertTrue(flags.contains(TcpHeader.Flag.PSH));
                assertTrue(flags.contains(TcpHeader.Flag.ACK));
                assertEquals(2, flags.size());
                assertTrue(tcpHeader.getOptions().isEmpty());

                TlsHeader tlsHeader = packet.getHeader(TlsHeader.Id);
                assertEquals(187, tlsHeader.getPayloadLength());
                assertEquals(TlsHeader.ContentType.Handshake, tlsHeader.getContentType());
                assertEquals(TlsHeader.Version.TLS1_0, tlsHeader.getVersion());
                assertFalse(tlsHeader.isFragmented());

                assertEquals(tlsHeader.getPayloadLength(), tlsHeader.getPayload().length);
                assertEquals(1, tlsHeader.getPayload()[0]);
            }
        });

    }

}
