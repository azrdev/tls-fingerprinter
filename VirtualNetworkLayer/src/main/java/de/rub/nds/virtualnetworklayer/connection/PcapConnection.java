package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.Signature;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

public class PcapConnection implements Connection {
    private PcapTrace trace = new PcapTrace();
    private Label[][] labels;
    private Signature session;
    private Socket socket;
    private Pcap pcap;
    private static int defaultTimeout = 1000;
    private int last;

    public static PcapConnection create(String host, int port) throws IOException {
        InetSocketAddress remoteSocketAddress = new InetSocketAddress(host, port);

        return attachSocket(remoteSocketAddress);
    }

    private static PcapConnection attachSocket(InetSocketAddress remoteSocketAddress) throws IOException {
        int port = findFreePort();

        InetSocketAddress localSocketAddress = new InetSocketAddress(InetAddress.getLocalHost(), port);
        Socket socket = new Socket();
        socket.bind(localSocketAddress);

        byte[] localAddress = Util.toAddress(localSocketAddress.getAddress());
        byte[] remoteAddress = Util.toAddress(remoteSocketAddress.getAddress());

        Signature session = new TcpHeader.Session(localAddress, remoteAddress,
                localSocketAddress.getPort(), remoteSocketAddress.getPort());

        Pcap pcap = Pcap.getInstance(localAddress);
        PcapConnection connection = ((ConnectionHandler) pcap.getHandler()).getConnection(session);
        connection.socket = socket;
        connection.pcap = pcap;

        socket.setSoTimeout(defaultTimeout);
        socket.connect(remoteSocketAddress, defaultTimeout);

        synchronized (connection) {
            try {
                while (connection.trace.size() < 3) {
                    connection.wait();
                }
            } catch (InterruptedException e) {

            }
        }

        return connection;
    }

    private static int findFreePort() throws IOException {
        ServerSocket server = new ServerSocket(0);
        int port = server.getLocalPort();
        server.close();

        return port;
    }

    PcapConnection(Signature session) {
        this.session = session;
        labels = new Label[Packet.Direction.values().length][ConnectionHandler.getFingerprintCount()];
    }

    private void checkSocket() throws IOException {
        if (socket == null) {
            TcpHeader.Session session = (TcpHeader.Session) this.session;
            InetSocketAddress remoteSocketAddress = new InetSocketAddress(Util.toIp4String(session.getDestinationAddress()), session.getDestinationPort());

            attachSocket(remoteSocketAddress);
        }
    }

    @Override
    public int available() throws IOException {
        return trace.size() - last;
    }

    public PcapPacket read(int timeout) throws IOException {
        checkSocket();

        int next;

        synchronized (this) {
            while ((next = trace.getNext(last, Packet.Direction.Response)) == last) {
                try {
                    this.wait(timeout);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        last = next;

        return trace.get(next);
    }

    public PcapPacket write(byte[] data) throws IOException {
        checkSocket();

        last = trace.getLast(Packet.Direction.Request);
        socket.getOutputStream().write(data);

        int next;

        synchronized (this) {
            while ((next = trace.getNext(last, Packet.Direction.Request)) == last) {
                try {
                    this.wait();
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        return trace.get(next);
    }

    void addLabel(Packet.Direction direction, Fingerprint print, Label label) {
        labels[direction.ordinal()][print.getId()] = label;
    }

    public PcapTrace getTrace() {
        return trace;
    }

    @Override
    public void close() throws IOException {
        if (socket != null && socket.isClosed()) {
            socket.close();
        }

        if (pcap != null) {
            pcap.finalize();
        }
    }

    public Label getLabel(Packet.Direction direction, int id) {
        return labels[direction.ordinal()][id];
    }

    public List<Label> getLabels(Packet.Direction direction) {
        return Arrays.asList(labels[direction.ordinal()]);
    }

    public Signature getSession() {
        return session;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
    }
}
