package de.rub.nds.virtualnetworklayer.connection.pcap;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Group;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_pkthdr;
import org.apache.log4j.Logger;
import org.bridj.Pointer;

import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * This class extends {@link PacketHandler} with session and fingerprinting capabilities.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see de.rub.nds.virtualnetworklayer.packet.header.Session
 * @see Fingerprint
 */
public abstract class ConnectionHandler extends PacketHandler {

    /**
     * TIMEOUT after which a connection should be considered dead and <b>be removed</b>
     * from the internal connection list (like TCP keepalive). In nanoseconds.
     */
	private static final long TIMEOUT = 120 * 1000000000L; // 120 seconds
    /**
     * Interval how often TIMEOUT should be checked - number of packets to newPacket()
     */
	private static final int TIMEOUT_INTERVAL = 5000; // Every 5000 Packets

    /**
     * A quiet connection handler discards all reporting.
     */
    public static class Quiet extends ConnectionHandler {

        @Override
        public void newConnection(Event event, PcapConnection connection) {
        }
    }

    public static enum Event {
        /**
         * new connection was reported
         */
        New,
        /**
         * new packet was added to an existing connection
         */
        Update
    }

    private static final Logger logger = Logger.getLogger(ConnectionHandler.class);

    private static Map<Fingerprint.Signature, Label>[] signatures;
    private static List<Fingerprint> prints = new LinkedList<>();

    private Map<SocketSession, PcapConnection> connections = new HashMap<>();
    /**
     * income packets since the last {@link #gc(long)}
     */
    private int timeout_counter = 0;

    static {
        signatures = (Map<Fingerprint.Signature, Label>[]) new HashMap<?, ?>[getHeaderCount()];
        for (int i = 0; i < signatures.length; i++) {
            signatures[i] = new HashMap<Fingerprint.Signature, Label>();
        }

        registerFingerprint(new MtuFingerprint());
        registerFingerprint(new TcpFingerprint());
    }

    /**
     * Register single signature
     *
     * @throws IllegalArgumentException if signature with identical signs is already registered
     */
    public static void registerSignature(Fingerprint.Signature signature, Label label) {
        Map<Fingerprint.Signature, Label> signatures = ConnectionHandler.signatures[label.getType().ordinal()];

        if (!signatures.containsKey(signature)) {
            signatures.put(signature, label);
        } else {
            throw new IllegalArgumentException("signature doubles " + signatures.get(signature));
        }
    }

    /**
     * Register all signatures from p0f file (p0f.fp)
     *
     * @param inputStream use {@link P0fFile#Embedded} for embedded p0f.fp
     */
    public static void registerP0fFile(InputStream inputStream) {
        P0fFile file = new P0fFile(inputStream);

        for (Group group : file.getGroups()) {
            int groupLine = 1;

            for (Fingerprint.Signature signature : group.getSignatures()) {
                try {
                    registerSignature(signature, group.getLabel());
                } catch (IllegalArgumentException e) {
                    logger.warn(group.getLabel() + ", " + groupLine + ". " + e.getMessage());
                }

                groupLine++;
            }
        }
    }

    /**
     * @return count of registered fingerprints
     */
    public static int getFingerprintCount() {
        return prints.size();
    }

    /**
     * Register single fingerprint.
     */
    public static void registerFingerprint(Fingerprint fingerprint) {
        prints.add(fingerprint);
    }

    PcapConnection getConnection(SocketSession session) {
        if (!connections.containsKey(session)) {
            connections.put(session, new PcapConnection(session));
            PcapConnection connection = connections.get(session);

            newConnection(Event.New, connection);

            return connection;
        } else {
            return connections.get(session);
        }
    }
    
    private void gc(long timestamp) {
    	HashMap<SocketSession, PcapConnection> tmp = new HashMap<SocketSession, PcapConnection>();
    	for (Entry<SocketSession, PcapConnection> e : this.connections.entrySet()) {
			if (e.getValue().getTrace().getLastTimeStamp() + TIMEOUT > timestamp) {
				tmp.put(e.getKey(), e.getValue());
			}
		}
    	int cleared = this.connections.size() - tmp.size();
    	if (cleared > 0) {
    		logger.debug("cleared " + cleared + " connections");
    	}
    	this.connections = tmp;
    	
    }

    @Override
    protected final void newPacket(PcapPacket packet) {
    	timeout_counter++;
    	if (timeout_counter > TIMEOUT_INTERVAL) {
    		this.gc(packet.getTimeStamp());
    		timeout_counter = 0;
    	}
        SocketSession session = packet.getSession();

        if (session != null) {
            PcapConnection connection = getConnection(session);
            if(connection.keepRawPackets())
                saveRawPacket(connection);

            packet.setDirection(connection.getSession().getDirection(packet));
            connection.getTrace().add(packet);

            for (Fingerprint print : prints) {
                if (print.isBound(packet)) {
                    Fingerprint.Signature signature = print.peer(packet, connection);
                    Label label = lookupSignature(signature);

                    connection.updateFingerprint(packet.getDirection(), print, signature, label);

                    if (label == null) {
                        logger.info(connection +
                                "\nunknown " + print.toString() +
                                ":\n" + signature.toString());
                    }
                }
            }

            synchronized (connection) {
                connection.notify();
                newConnection(Event.Update, connection);
            }
        }
    }

    protected void saveRawPacket(PcapConnection connection) {
        connection.getRawPackets().add(getCurrentRawPacket());
    }

    private Label lookupSignature(Fingerprint.Signature signature) {
        for (int i = 0; i < signatures.length; i++) {
            if (signatures[i].containsKey(signature)) {
                return signatures[i].get(signature);
            }

            signature.setFuzzy(true);
            if (signatures[i].containsKey(signature)) {
                return signatures[i].get(signature);
            }
        }

        return null;
    }

    public List<PcapConnection> getConnections() {
        return new LinkedList<>(connections.values());
    }


    /**
     * Connection event.
     * Callback method has to be non-blocking.
     *
     * @param event      cause of invocation
     * @param connection the event source
     */
    public abstract void newConnection(Event event, PcapConnection connection);
}
