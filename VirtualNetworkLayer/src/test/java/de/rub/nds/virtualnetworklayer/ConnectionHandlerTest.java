package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.FragmentSequence;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.application.HttpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.application.SipHeader;
import de.rub.nds.virtualnetworklayer.packet.header.application.SmtpHeader;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;

public class ConnectionHandlerTest {

    private static String path = PacketHandlerTest.class.getResource("").getPath();
    private static PcapConnection pcapConnection;

    @BeforeClass
    public static void setUpBeforeClass() throws FileNotFoundException {
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);
    }

    @Test
    public void serverHelloTlsFragmented() {
        File file = new File(path, "serverHelloTlsFragmented.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
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

        List<FragmentSequence> fragmentSequences = pcapTrace.getFragmentSequences();
        assertEquals(1, fragmentSequences.size());

        FragmentSequence sequence = fragmentSequences.get(0);
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
    public void tcpSegmentLost() {
        File file = new File(path, "tcpSegmentLost.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        assertEquals(1, pcapConnection.getTrace().getRetransmitted().size());

        List<FragmentSequence> fragmentSequences = pcapConnection.getTrace().getFragmentSequences();
        assertEquals(1, fragmentSequences.size());

        FragmentSequence sequence = fragmentSequences.get(0);
        PcapPacket extendedPacket = sequence.getExtendedPacket();
        assertTrue(extendedPacket.hasHeader(HttpHeader.Id));
        assertEquals(24456, extendedPacket.getLength());

        assertNull(sequence.getCroppedPacket());
    }

    @Test
    public void udpSip() {
        File file = new File(path, "udpSip.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        PcapTrace trace = pcapConnection.getTrace();
        assertEquals(1, trace.size());

        SipHeader header = trace.get(0).getHeader(Headers.Sip);
        assertEquals(Packet.Direction.Response, header.getDirection());
        assertEquals(8, header.getHeaders().size());
        assertEquals(180, header.getStatusCode());
    }

    @Test
    public void smtpStartTls() {
        File file = new File(path, "smtpStartTls.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                pcapConnection = connection;
            }
        });

        PcapTrace trace = pcapConnection.getTrace();
        assertEquals(5, trace.size());

        SmtpHeader header = trace.get(0).getHeader(Headers.Smtp);
        LinkedList<SmtpHeader.Command> commands = header.getCommands();
        assertEquals(220, commands.getFirst().getStatusCode());

        header = trace.get(1).getHeader(Headers.Smtp);
        commands = header.getCommands();
        assertEquals("EHLO", commands.getFirst().getAction());

        header = trace.get(2).getHeader(Headers.Smtp);
        for (SmtpHeader.Command command : header.getCommands()) {
            assertEquals(250, command.getStatusCode());
        }

        header = trace.get(3).getHeader(Headers.Smtp);
        commands = header.getCommands();
        assertEquals("STARTTLS", commands.getFirst().getAction());
    }

    @Test
    public void pcapTraceIterator() throws FileNotFoundException {
        File file = new File(path, "tcpHandshake.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
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

    @Test
    public void tcpHandshakeFingerprint() throws FileNotFoundException {
        File file = new File(path, "tcpHandshake.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
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

    @Test
    public void httpsGoogleFingerprint() throws FileNotFoundException {
        File file = new File(path, "httpsGoogle.pcap");
        Pcap pcap = Pcap.openOffline(file);

        ConnectionHandler handler = new ConnectionHandler.Quiet();
        pcap.loop(handler);

        assertEquals(19, handler.getConnections().size());
    }

    @Test
    public void httpFreeBSDFingerprint() throws FileNotFoundException {
        File file = new File(path, "httpFreeBSD.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
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
            public void newConnection(Event event, PcapConnection connection) {
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

    @Test
    public void tcpSynAckCiscoFingerprint() throws FileNotFoundException {
        File file = new File(path, "tcpSynAckCisco.pcap");
        Pcap pcap = Pcap.openOffline(file);

        pcap.loop(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                if (event == Event.New) {
                    pcapConnection = connection;
                }
            }
        });

        Label mtuLabel = pcapConnection.getLabel(Packet.Direction.Response, MtuFingerprint.Id);
        assertEquals("generic tunnel or VPN", mtuLabel.getFlavor());

        Label tcpLabel = pcapConnection.getLabel(Packet.Direction.Response, TcpFingerprint.Id);
        assertEquals("Cisco PIX OS", tcpLabel.getName());
        assertEquals("unix", tcpLabel.getLabelClass());
        assertEquals("8.x", tcpLabel.getFlavor());
    }

}
