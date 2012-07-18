package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.DhcpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ArpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.Ethernet;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.EthernetHeader;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.IEEE802_2Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ethernet.IEEE802_3Header;
import de.rub.nds.virtualnetworklayer.packet.header.link.ppp.PPPoEHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.transport.UdpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;

import static junit.framework.Assert.*;

public class PacketHandlerTest {
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
    public void ipPPPoE() {
        File file = new File(getClass().getResource("ipPPPoE.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        CountingPacketHandler packetHandler = new CountingPacketHandler();
        pcap.loop(packetHandler);

        assertEquals(65, packetHandler.getHeaderCount(EthernetHeader.Id));
        assertEquals(65, packetHandler.getHeaderCount(PPPoEHeader.Id));
        assertEquals(25, packetHandler.getHeaderCount(Ip6Header.Id));
    }

    @Test
    public void ethernetTrailer() {
        File file = new File(getClass().getResource("ethernetTrailer.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                EthernetHeader ethernetHeader = packet.getHeader(Headers.Ethernet);

                TcpHeader tcpHeader = packet.getHeader(Headers.Tcp);
                assertEquals(0, tcpHeader.getPayloadLength());
            }
        });
    }

    @Test
    public void arp() {
        File file = new File(getClass().getResource("arp.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                ArpHeader header = packet.getHeader(Headers.Arp);
                if (header.getOperation() == 1) {
                    assertEquals(1, header.getHardwareType());
                    assertEquals(Ethernet.Type.Ip4, header.getProtocolType());
                    assertEquals(6, header.getHardwareAddressLength());
                    assertEquals(4, header.getProtocolAddressLength());
                    assertEquals(1, header.getOperation());
                    assertEquals("60:33:4b:0b:42:16", MacFormatter.toString(header.getSenderHardwareAddress()));
                    assertEquals("00:00:00:00:00:00", MacFormatter.toString(header.getTargetHardwareAddress()));
                    assertEquals("192.168.6.20", IpFormatter.toIp4String(header.getSenderProtocolAddress()));
                    assertEquals("192.168.6.1", IpFormatter.toIp4String(header.getTargetProtocolAddress()));
                }
            }
        });
    }

    @Test
    public void logicalLinkControl() {
        File file = new File(getClass().getResource("logicalLinkControl.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                IEEE802_3Header ethernet = packet.getHeader(Headers.IEEE802_3);
                assertEquals(235, ethernet.getPayloadLength());
                assertEquals("ff:ff:ff:ff:ff:ff", MacFormatter.toString(ethernet.getDestinationMac()));
                assertEquals("00:40:68:5b:ea:69", MacFormatter.toString(ethernet.getSourceMac()));

                IEEE802_2Header llcHeader = packet.getHeader(Headers.IEEE802_2);
                assertEquals(0xba, llcHeader.getDestinationServiceAccessPoint());
                assertEquals(0xba, llcHeader.getSourceServiceAccessPoint());
                assertEquals(0x03, llcHeader.getControl());
                assertEquals(232, llcHeader.getPayload().length);
            }
        });
    }


    @Test
    public void ipDhcp() {
        File file = new File(getClass().getResource("ipDhcp.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                DhcpHeader header = packet.getHeader(Headers.Dhcp);
                assertEquals(DhcpHeader.MessageType.Discover, header.getMessageType());
                assertEquals(1, header.getHardwareType());
                assertEquals(6, header.getHardwareAddressLength());
                assertEquals(0, header.getHops());
                assertEquals(0x5758bf9d, header.getTransactionId());
                assertEquals(0, header.getSecondsElapsed());
                assertEquals(0, header.getFlags());
                assertEquals("0.0.0.0", IpFormatter.toString(header.getClientIpAddress()));
                assertEquals("0.0.0.0", IpFormatter.toString(header.getYourIpAddress()));
                assertEquals("0.0.0.0", IpFormatter.toString(header.getServerIpAddress()));
                assertEquals("0.0.0.0", IpFormatter.toString(header.getGatewayIpAddress()));

                assertEquals("", header.getServerHostName());
                assertEquals("", header.getBootFileName());

                List<Header.Option<Integer>> options = header.getOptions();
                assertEquals(53, (int) options.get(0).getType());
                assertEquals(55, (int) options.get(1).getType());
                assertEquals(57, (int) options.get(2).getType());
                assertEquals(61, (int) options.get(3).getType());
                assertEquals(50, (int) options.get(4).getType());
                assertEquals(51, (int) options.get(5).getType());
            }
        });
    }

    @Test
    public void httpsGoogle() {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
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
        File file = new File(getClass().getResource("serverHelloTlsFragmented.pcap").getPath());
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
        File file = new File(getClass().getResource("clientHelloTls.pcap").getPath());
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
                assertEquals("192.168.1.58", IpFormatter.toString(ip4Header.getSourceAddress()));
                assertEquals("74.125.79.95", IpFormatter.toString(ip4Header.getDestinationAddress()));

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
