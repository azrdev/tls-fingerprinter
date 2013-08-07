package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.Connection;
import de.rub.nds.virtualnetworklayer.connection.socket.SocketConnection;
import de.rub.nds.virtualnetworklayer.connection.socket.SocketTrace;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;

import static org.junit.Assert.*;

public class SocketConnectionTest {
    private static int timeOut = Connection.DefaultTimeout * 1000 * 1000;
    private static String request = "GET / HTTP/1.0 \r\n\r\n";

    @Test
    public void response() throws IOException {
        Connection connection = SocketConnection.create("www.google.de", 80);

        String request = "GET / HTTP/1.0 \n\n";
        connection.write(request.getBytes());

        Packet packet = connection.read(timeOut);
        String response = new String(packet.getContent());

        assertEquals(Packet.Direction.Response, packet.getDirection());
        assertTrue(response.startsWith("HTTP/1.0 302 Found"));
        assertEquals(Util.now(), packet.getTimeStamp(), timeOut);
    }

    @Test(expected = SocketTimeoutException.class)
    public void connectionTimeout() throws IOException {
        SocketConnection.create("www.google.de", 5387);
    }

    @Test
    public void available() throws IOException, InterruptedException {
        Connection connection = SocketConnection.create("www.google.de", 80);

        connection.write(request.getBytes());
        Thread.sleep(50);

        assertNotSame(0, connection.available());
    }

    @Test
    public void request() throws IOException {
        SocketConnection connection = SocketConnection.create("www.google.de", 80);

        connection.write(request.getBytes());

        assertEquals(1, connection.getTrace().size());

        Packet packet = connection.getTrace().get(0);
        assertEquals(Packet.Direction.Request, packet.getDirection());
        assertArrayEquals(request.getBytes(), packet.getContent());
        assertEquals(Util.now(), packet.getTimeStamp(), timeOut);
    }

    @Test
    public void trace() throws IOException {
        SocketConnection connection = SocketConnection.create("www.google.de", 80);

        connection.write(request.getBytes());
        connection.read(timeOut);

        String requestImghp = "GET /imghp HTTP/1.0 \n\n";
        connection.write(requestImghp.getBytes());
        connection.read(timeOut);

        String requestNewshp = "GET /newshp HTTP/1.0 \n\n";
        connection.write(requestNewshp.getBytes());
        connection.read(timeOut);

        assertEquals(6, connection.getTrace().size());
    }

    @Test(expected = SocketTimeoutException.class)
    public void timeout() throws IOException {
        SocketConnection connection = SocketConnection.create("www.google.de", 80);

        connection.write(request.getBytes());

        connection.read(10);
    }

    @Test
    public void trafficCount() throws IOException {
        SocketConnection connection = SocketConnection.create("www.google.de", 80);

        connection.write(request.getBytes());

        Packet packet = connection.read(timeOut);

        SocketTrace trace = connection.getTrace();

        assertEquals(19, trace.getTrafficVolumeBetween(0, packet.getTimeStamp() - 1));
        assertEquals(packet.getContent().length, trace.getTrafficVolumeBetween(packet.getTimeStamp(), Util.now()));
    }

}
