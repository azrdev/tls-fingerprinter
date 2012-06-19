package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.PcapTrace;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConnectionHandlerTest {

    public class QueuingConnectionHandler extends ConnectionHandler {
        private Queue<PcapConnection> connections = new ArrayBlockingQueue<PcapConnection>(10);

        @Override
        public void newConnection(PcapConnection connection) {
            connections.add(connection);
        }

        public Queue<PcapConnection> getConnections() {
            return connections;
        }
    }

    private static String path = PacketHandlerTest.class.getResource("").getPath();
    private static PcapConnection pcapConnection;

    @BeforeClass
    public static void setUpBeforeClass() throws FileNotFoundException {
        ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));
    }

    @Test
    public void serverHelloTlsFragmented() {
        File file = new File(path, "serverHelloTlsFragmented.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        PcapTrace pcapTrace = pcapConnection.getTrace();
        assertEquals(2, pcapTrace.size());

        Iterator<PcapPacket> iterator = pcapTrace.iterator();

        PcapPacket packet = iterator.next();
        assertEquals(1337775365308L, packet.getTimeStamp());
        packet = iterator.next();
        assertEquals(1337775365978L, packet.getTimeStamp());

        List<PcapTrace.FragmentSequence> fragmentSequences = pcapTrace.getFragmentSequences();
        assertEquals(1, fragmentSequences.size());

        PcapTrace.FragmentSequence sequence = fragmentSequences.get(0);
        assertEquals(2, sequence.getPackets().size());
        assertEquals(1601, sequence.getReassembledPayloadLength());

        assertEquals(sequence.getReassembledPayloadLength(), sequence.getReassembledPayload().length);

        PcapPacket croppedPacket = sequence.getCroppedPacket();
        assertEquals(151, croppedPacket.getLength());
        assertTrue(croppedPacket.hasHeader(TlsHeader.Id));

        PcapPacket extendedPacket = sequence.getExtendedPacket();
        assertEquals(1872, extendedPacket.getLength());
        assertTrue(extendedPacket.hasHeader(TlsHeader.Id));
        TlsHeader header = extendedPacket.getHeader(TlsHeader.Id);
        assertEquals(TlsHeader.ContentType.Handshake, header.getContentType());
        assertEquals(1596, header.getPayloadLength());

        header = extendedPacket.getHeader(TlsHeader.Id, 1);
        assertEquals(TlsHeader.ContentType.Handshake, header.getContentType());
        assertEquals(203, header.getPayloadLength());

        header = extendedPacket.getHeader(TlsHeader.Id, 2);
        assertEquals(TlsHeader.ContentType.Handshake, header.getContentType());
        assertEquals(4, header.getPayloadLength());
    }

    @Test
    public void pcapTraceIterator() throws FileNotFoundException {
        File file = new File(path, "tcpHandshake.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        assertEquals(3, pcapConnection.getTrace().size());

        boolean requestResponseFlag = true;
        for (Packet packet : pcapConnection.getTrace()) {
            if (requestResponseFlag) {
                assertEquals(Packet.Direction.Request, packet.getDirection());
            } else {
                assertEquals(Packet.Direction.Response, packet.getDirection());
            }

            requestResponseFlag = !requestResponseFlag;
        }
    }

    //@Test
    public void httpsGoogleFragmented() {
        File file = new File(path, "httpsGoogle.pcap");
        Pcap pcap = Pcap.openOffline(file);
        pcap.filter("src host 173.194.35.184 and tcp port 443");

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        System.out.println(pcapConnection.getTrace().size());

    }

    @Test
    public void tcpHandshakeFingerprint() throws FileNotFoundException {
        File file = new File(path, "tcpHandshake.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        Label mtuLabel = pcapConnection.getLabel(Packet.Direction.Response, MtuFingerprint.Id);
        assertEquals("Google", mtuLabel.getFlavor());

        mtuLabel = pcapConnection.getLabel(Packet.Direction.Request, MtuFingerprint.Id);
        assertEquals("generic tunnel or VPN", mtuLabel.getFlavor());

        Label tcpLabel = pcapConnection.getLabel(Packet.Direction.Response, TcpFingerprint.Id);
        assertEquals("Linux", tcpLabel.getName());
        assertEquals("unix", tcpLabel.getLabelClass());
        assertEquals("3.x", tcpLabel.getFlavor());

        tcpLabel = pcapConnection.getLabel(Packet.Direction.Request, TcpFingerprint.Id);
        List<Label> labels = pcapConnection.getLabels(Packet.Direction.Response);

        assertEquals("Windows", tcpLabel.getName());
        assertEquals("win", tcpLabel.getLabelClass());
        assertEquals("7 or 8", tcpLabel.getFlavor());
    }

    //@Test
    public void httpsGoogleFingerprint() throws FileNotFoundException {
        File file = new File(path, "httpsGoogle.pcap");
        Pcap pcap = Pcap.openOffline(file);

        QueuingConnectionHandler connectionHandler = new QueuingConnectionHandler();
        pcap.loop(connectionHandler);

        Queue<PcapConnection> queue = connectionHandler.getConnections();
        /*queue.remove();
        queue.remove();

        System.out.println(queue.peek().getSession());

        System.out.println(queue.peek().getLabels(Packet.Direction.Response));*/
    }

    @Test
    public void httpFreeBSDFingerprint() throws FileNotFoundException {
        File file = new File(path, "httpFreeBSD.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        Label mtuLabel = pcapConnection.getLabel(Packet.Direction.Response, MtuFingerprint.Id);
        assertEquals("Ethernet or modem", mtuLabel.getFlavor());

        Label tcpLabel = pcapConnection.getLabel(Packet.Direction.Response, TcpFingerprint.Id);
        assertEquals("FreeBSD", tcpLabel.getName());
        assertEquals("unix", tcpLabel.getLabelClass());
        assertEquals("8.x", tcpLabel.getFlavor());
    }

    @Test
    public void tcpSynMacOSXFingerprint() throws FileNotFoundException {
        File file = new File(path, "tcpSynMacOSX.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        Label mtuLabel = pcapConnection.getLabel(Packet.Direction.Request, MtuFingerprint.Id);
        assertEquals("Ethernet or modem", mtuLabel.getFlavor());

        Label tcpLabel = pcapConnection.getLabel(Packet.Direction.Request, TcpFingerprint.Id);
        assertEquals("Mac OS X", tcpLabel.getName());
        assertEquals("unix", tcpLabel.getLabelClass());
        assertEquals("10.x", tcpLabel.getFlavor());
    }

}
