package de.rub.nds.virtualnetworklayer.connection.socket;

import de.rub.nds.virtualnetworklayer.connection.Connection;
import de.rub.nds.virtualnetworklayer.packet.BytePacket;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * This class implements a connection solely based on sockets api.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Socket
 */
public class SocketConnection implements Connection {
    private Socket socket;
    private SocketTrace trace;

    /**
     * Creates a connection and connects to the specified port number at the specified IP address.
     * {@link #DefaultTimeout} is used.
     *
     * @param host
     * @param port
     * @return connection
     * @throws IOException
     */
    public static SocketConnection create(String host, int port) throws IOException {
        return new SocketConnection(host, port, Connection.DefaultTimeout);
    }

    /**
     * Creates a connection and connects to the specified port number at the specified IP address.
     *
     * @param host
     * @param port
     * @param timeout in milliseconds
     * @return connection
     * @throws IOException
     */
    public static SocketConnection create(String host, int port, int timeout) throws IOException {
        return new SocketConnection(host, port, timeout);
    }

    private SocketConnection(String host, int port, int timeout) throws IOException {
        trace = new SocketTrace();

        socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), timeout);
    }

    /**
     * @return number of available bytes
     * @throws IOException
     * @see InputStream
     */
    @Override
    public int available() throws IOException {
        return socket.getInputStream().available();
    }

    @Override
    public BytePacket read(int timeout) throws IOException {
        socket.setSoTimeout(timeout);
        InputStream inputStream = socket.getInputStream();

        ByteArrayOutputStream content = new ByteArrayOutputStream();

        int b;
        while ((b = inputStream.read()) != -1) {
            content.write(b);
        }

        BytePacket packet = new BytePacket(content.toByteArray(), Packet.Direction.Response);
        trace.add(packet);

        return packet;
    }

    @Override
    public BytePacket write(byte[] data) throws IOException {
        socket.getOutputStream().write(data);
        BytePacket newPacket = new BytePacket(data, Packet.Direction.Request);
        trace.add(newPacket);

        return newPacket;
    }

    @Override
    public SocketTrace getTrace() {
        return trace;
    }

    @Override
    public void close() {
        if (socket.isConnected()) {
            try {
                socket.close();
            } catch (IOException e) {
                socket = null;
            }
        }
    }

    @Override
    public String toString() {
        byte[] localAddress = Util.toAddress(socket.getLocalAddress());
        byte[] remoteAddress = Util.toAddress(socket.getInetAddress());

        return "[" + IpFormatter.toString(localAddress) + ", " + socket.getLocalPort() + " | " + IpFormatter.toString(remoteAddress) + ", " + socket.getPort() + "]";
    }

    @Override
    protected void finalize() throws Throwable {
        close();
    }
}
