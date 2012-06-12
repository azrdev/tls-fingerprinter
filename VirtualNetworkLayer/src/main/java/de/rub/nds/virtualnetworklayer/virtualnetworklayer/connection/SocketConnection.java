package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.BytePacket;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class SocketConnection implements Connection {

    public class PacketTrace extends Trace<BytePacket> {
        private List<BytePacket> packets = new ArrayList<BytePacket>();

        public BytePacket get(int position) {
            return packets.get(position);
        }

        public int size() {
            return packets.size();
        }

        @Override
        public Iterator<BytePacket> iterator() {
            return packets.iterator();
        }
    }

    private Socket socket;
    private static int defaultTimeout = 1000;
    private PacketTrace trace;

    public SocketConnection(String host, int port) throws IOException {
        this(host, port, defaultTimeout);
    }

    public SocketConnection(String host, int port, int timeout) throws IOException {
        trace = new PacketTrace();

        socket = new Socket();
        socket.setSoTimeout(timeout);
        socket.connect(new InetSocketAddress(host, port), timeout);
    }

    @Override
    public Packet read(int timeout) throws IOException {
        socket.setSoTimeout(timeout);
        InputStream inputStream = socket.getInputStream();

        ByteArrayOutputStream content = new ByteArrayOutputStream();

        int b;
        while ((b = inputStream.read()) != -1) {
            content.write(b);
        }

        BytePacket packet = new BytePacket(content.toByteArray(), Packet.Direction.Response);
        trace.packets.add(packet);

        return packet;
    }

    @Override
    public void write(byte[] data) throws IOException {
        socket.getOutputStream().write(data);
        trace.packets.add(new BytePacket(data, Packet.Direction.Request));
    }

    public long getTrafficCountBetween(long from, long to) {
        int position = Math.abs(Collections.binarySearch(trace.packets, from) + 1);

        long trafficCount = 0;
        for (int i = position; i < trace.size() && trace.get(i).getTimeStamp() <= to; i++) {
            trafficCount += trace.get(i).getContent().length;
        }

        return trafficCount;
    }

    @Override
    public PacketTrace getTrace() {
        return trace;
    }

    @Override
    protected void finalize() throws Throwable {
        if (socket.isConnected()) {
            socket.close();
        }
    }
}
