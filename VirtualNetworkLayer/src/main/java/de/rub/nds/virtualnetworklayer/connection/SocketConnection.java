package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.BytePacket;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class SocketConnection implements Connection {
    private Socket socket;
    private static int defaultTimeout = 1000;
    private SocketTrace trace;

    public static SocketConnection create(String host, int port) throws IOException {
        return new SocketConnection(host, port);
    }

    private SocketConnection(String host, int port) throws IOException {
        this(host, port, defaultTimeout);
    }

    private SocketConnection(String host, int port, int timeout) throws IOException {
        trace = new SocketTrace();

        socket = new Socket();
        socket.setSoTimeout(timeout);
        socket.connect(new InetSocketAddress(host, port), timeout);
    }

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
    protected void finalize() throws Throwable {
        if (socket.isConnected()) {
            socket.close();
        }
    }
}
