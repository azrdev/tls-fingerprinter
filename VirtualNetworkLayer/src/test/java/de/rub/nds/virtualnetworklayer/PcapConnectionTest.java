package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static junit.framework.Assert.assertFalse;
import static org.junit.Assert.*;

public class PcapConnectionTest {
    private static String path = PacketHandlerTest.class.getResource("").getPath();

    @BeforeClass
    public static void setUpBeforeClass() throws FileNotFoundException {
        ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));
    }

    @Test(timeout = 1000)
    public void handshake() throws IOException {
        PcapConnection connection = PcapConnection.create("www.google.de", 80);
    }

    @Test(timeout = 2000)
    public void request() throws IOException {
        PcapConnection connection = PcapConnection.create("www.google.de", 80);

        String request = "GET / HTTP/1.0 \n\n";

        PcapPacket packet = connection.write(request.getBytes());
        Ip4Header ipHeader = packet.getHeader(Ip4Header.Id);

        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
        assertArrayEquals(request.getBytes(), tcpHeader.getPayload());
        assertFalse(packet.isFragmented());
    }

    @Test
    public void available() throws IOException, InterruptedException {
        PcapConnection connection = PcapConnection.create("www.google.de", 80);

        String request = "GET / HTTP/1.0 \n\n";
        connection.write(request.getBytes());

        Thread.sleep(50);
        assertNotSame(0, connection.available());
    }

    @Test
    public void response() throws IOException {
        PcapConnection connection = PcapConnection.create("www.google.de", 80);

        String request = "GET / HTTP/1.0 \n\n";
        connection.write(request.getBytes());

        connection.read(1000);
        PcapPacket packet = connection.read(1000);
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        String response = new String(tcpHeader.getPayload());
        Assert.assertTrue(response.startsWith("HTTP/1.0 302 Found"));
    }


    @Test(timeout = 1000)
    public void tcpHandshakeFingerprint() throws IOException {
        PcapConnection connection = PcapConnection.create("www.google.de", 80);

        Label mtuLabel = connection.getLabel(Packet.Direction.Response, MtuFingerprint.Id);
        assertEquals("Google", mtuLabel.getFlavor());

        mtuLabel = connection.getLabel(Packet.Direction.Request, MtuFingerprint.Id);
        assertEquals("Ethernet or modem", mtuLabel.getFlavor());

        Label tcpLabel = connection.getLabel(Packet.Direction.Response, TcpFingerprint.Id);
        assertEquals("Linux", tcpLabel.getName());
        assertEquals("unix", tcpLabel.getLabelClass());
        assertEquals("2.2.x-3.x", tcpLabel.getFlavor());
    }

}
