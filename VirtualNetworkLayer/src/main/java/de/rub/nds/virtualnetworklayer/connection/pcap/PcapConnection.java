package de.rub.nds.virtualnetworklayer.connection.pcap;

import de.rub.nds.virtualnetworklayer.connection.Connection;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.link.family.Family;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * This class implements a connection based on sockets api and pcap
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Socket
 * @see Pcap
 */
public class PcapConnection implements Connection {
    private static Logger logger = Logger.getLogger(PcapConnection.class);

    private PcapTrace trace = new PcapTrace();
    private Label[][] labels;
    private Fingerprint.Signature[][] signatures;
    private SocketSession session;

    private Socket socket;
    private Pcap pcap;
    private int lastPacketPosition;

    private boolean keepRawPackets = false;

    private List<ConnectionHandler.RawPacket> rawPackets = new LinkedList<>();

    /**
     * Creates a connection and connects to the specified port number at the specified IP address.
     * {@link #DefaultTimeout} is used.
     *
     * @param host
     * @param port
     * @return connection
     * @throws IOException
     */
    public static PcapConnection create(String host, int port) throws IOException {
        String device = IpFormatter.toString(Pcap.getLiveDevice(host).getAddress(Family.Category.Ip4));
        return create(host, port, device);
    }

    /**
     * Creates a connection and connects to the specified port number at the specified IP address.
     * {@link #DefaultTimeout} is used.
     *
     * @param host
     * @param port
     * @return connection
     * @throws IOException
     */
    public static PcapConnection create(String host, int port, String device) throws IOException {
        return create(host, port, device, DefaultTimeout);
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
    public static PcapConnection create(String host, int port, String device, int timeout) throws IOException {
        InetSocketAddress remoteSocketAddress = new InetSocketAddress(host, port);

        return attachSocket(remoteSocketAddress, device, timeout);
    }

    private static PcapConnection attachSocket(InetSocketAddress remoteSocketAddress, String device, int timeout) throws IOException {
        int port = findFreePort();
        
        InetSocketAddress localSocketAddress = new InetSocketAddress(device, port);
        Socket socket = new Socket();
        if (!device.equals("0.0.0.0")) {
            socket.bind(localSocketAddress);
        }

        byte[] localAddress = Util.toAddress(localSocketAddress.getAddress());
        byte[] remoteAddress = Util.toAddress(remoteSocketAddress.getAddress());

        SocketSession session = new SocketSession(localAddress, remoteAddress,
                localSocketAddress.getPort(), remoteSocketAddress.getPort());

        Pcap pcap = Pcap.getInstanceForRemoteHost(remoteSocketAddress.getAddress().getHostAddress());
        pcap.loopAsynchronous(new ConnectionHandler.Quiet());

        PcapConnection connection = ((ConnectionHandler) pcap.getHandler()).getConnection(session);
        connection.socket = socket;
        connection.pcap = pcap;
        
        try {
            socket.connect(remoteSocketAddress, timeout);
        } catch (IOException e) {
            pcap.close();
            System.err.println("Failed to connect to: " + remoteSocketAddress.toString());
            System.err.println("Local address was: " + localSocketAddress.toString());
            System.err.println("Device was: " + device);
            e.printStackTrace();
            throw e;
        }
        
        synchronized (connection) {
            try {
                while (connection.trace.size() < 3) {
                    // TODO deadlocked
                    logger.debug("deadlocked: " + connection);
                    connection.wait();
                }
            } catch (InterruptedException e) {}
        }

        return connection;
    }

    private static int findFreePort() throws IOException {
        ServerSocket server = new ServerSocket(0);
        int port = server.getLocalPort();
        server.close();

        return port;
    }

    PcapConnection(SocketSession session) {
        this.session = session;
        labels = new Label[Packet.Direction.values().length][ConnectionHandler.getFingerprintCount()];
        signatures = new Fingerprint.Signature[Packet.Direction.values().length][ConnectionHandler.getFingerprintCount()];
    }

    private void checkSocket() throws IOException {
        if (socket == null) {
            SocketSession session = (SocketSession) this.session;
            String host = IpFormatter.toString(session.getDestinationAddress());
            InetSocketAddress remoteSocketAddress = new InetSocketAddress(host, session.getDestinationPort());
            String liveDevice = IpFormatter.toString(Pcap.getLiveDevice(host).getAddress(Family.Category.Ip4));

            attachSocket(remoteSocketAddress, liveDevice, DefaultTimeout);
        }
    }

    /**
     * @return number of available packets
     * @throws IOException
     * @see Packet
     */
    @Override
    public int available() throws IOException {
        return trace.size() - lastPacketPosition;
    }

    public PcapPacket read(int timeout) throws IOException {
        checkSocket();

        int next;
        long start = Util.now();

        synchronized (this) {
            while ((next = trace.getNextPosition(lastPacketPosition, Packet.Direction.Response)) == lastPacketPosition) {
                try {
                    this.wait(timeout);

                    if ((Util.now() - start) >= timeout * 1000 * 1000) {
                        break;
                    }

                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        lastPacketPosition = next;

        return trace.get(next);
    }

    public PcapPacket write(byte[] data) throws IOException {
        checkSocket();

        lastPacketPosition = trace.getLastPosition(Packet.Direction.Request);
        socket.getOutputStream().write(data);

        int next;

        synchronized (this) {
            while ((next = trace.getNextPosition(lastPacketPosition, Packet.Direction.Request)) == lastPacketPosition) {
                try {
                    // TODO deadlocked
                    this.wait();
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        return trace.get(next);
    }

    void updateFingerprint(Packet.Direction direction, Fingerprint print,
                           Fingerprint.Signature signature, Label label) {
        if (getLabel(direction, print.getId()) == null
		        || getLabel(direction, print.getId()).compareTo(label) < 0) {
            labels[direction.ordinal()][print.getId()] = label;
            signatures[direction.ordinal()][print.getId()] = signature;
        }
    }

    public PcapTrace getTrace() {
        return trace;
    }

    @Override
    public void close() {
        if (socket != null && socket.isClosed()) {
            try {
                socket.close();
            } catch (IOException e) {
                socket = null;
            }
        }

        if (pcap != null) {
            pcap.close();
        }
    }

    public Label getLabel(Packet.Direction direction, int id) {
        return labels[direction.ordinal()][id];
    }

    public Label getLabel(Packet.Direction direction, Fingerprints print) {
        return getLabel(direction, print.ordinal());
    }

    public List<Label> getLabels(Packet.Direction direction) {
        return Arrays.asList(labels[direction.ordinal()]);
    }

    public Fingerprint.Signature getSignature(Packet.Direction direction, int id) {
        return signatures[direction.ordinal()][id];
    }

    public Fingerprint.Signature getSignature(Packet.Direction direction, Fingerprints print) {
        return getSignature(direction, print.ordinal());
    }

    public List<Fingerprint.Signature> getSignatures(Packet.Direction direction) {
        return Arrays.asList(signatures[direction.ordinal()]);
    }

    public SocketSession getSession() {
        return session;
    }

    @Override
    public String toString() {
        return session.toString();
    }

    @Override
    protected void finalize() throws Throwable {
        close();
    }

    public boolean keepRawPackets() {
        return keepRawPackets;
    }

    public void setKeepRawPackets(boolean keepRawPackets) {
        setKeepRawPackets(keepRawPackets, false);
    }

    /**
     * @param keepCurrent If true, don't throw away currently kept raw packets when
     *                    setting keepRawPackets to false
     */
    public void setKeepRawPackets(boolean keepRawPackets, boolean keepCurrent) {
        this.keepRawPackets = keepRawPackets;
        if(! keepRawPackets && ! keepCurrent) {
            rawPackets.clear();
        }
    }

    public List<ConnectionHandler.RawPacket> getRawPackets() {
        return rawPackets;
    }
}
