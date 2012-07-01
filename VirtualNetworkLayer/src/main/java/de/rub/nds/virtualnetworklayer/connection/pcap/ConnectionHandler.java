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

import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * This class extends {@link PacketHandler} with session and fingerprinting capabilities.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see de.rub.nds.virtualnetworklayer.packet.header.Session
 * @see Fingerprint
 */
public abstract class ConnectionHandler extends PacketHandler {

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

    private final static Logger logger = Logger.getLogger(ConnectionHandler.class.getName());

    private static Map<Fingerprint.Signature, Label>[] signatures;
    private static List<Fingerprint> prints = new LinkedList<Fingerprint>();

    private HashMap<SocketSession, PcapConnection> connections = new HashMap<SocketSession, PcapConnection>();

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
     * @param signature
     * @param label
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
                    logger.warning(group.getLabel() + ", " + groupLine + ". " + e.getMessage());
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
     *
     * @param fingerprint
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

    @Override
    protected final void newPacket(PcapPacket packet) {
        SocketSession session = packet.getSession();

        if (session != null) {
            PcapConnection connection = getConnection(session);

            packet.setDirection(connection.getSession().getDirection(packet));
            connection.getTrace().add(packet);

            for (Fingerprint print : prints) {
                if (print.isBound(packet)) {
                    Fingerprint.Signature signature = print.peer(packet, connection);
                    Label label = lookupSignature(signature);

                    if (label != null) {
                        connection.updateFingerprint(packet.getDirection(), print, signature, label);
                    } else {
                        logger.info(connection + "\nunknown " + print.toString() + ":\n" + signature.toString());
                    }
                }
            }

            synchronized (connection) {
                connection.notify();
                newConnection(Event.Update, connection);
            }
        }
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
        return new LinkedList<PcapConnection>(connections.values());
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
