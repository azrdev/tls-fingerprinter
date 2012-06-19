package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Group;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.util.Signature;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public abstract class ConnectionHandler extends PacketHandler {
    public static class Quiet extends ConnectionHandler {

        @Override
        public void newConnection(PcapConnection connection) {
        }
    }

    private final static Logger logger = Logger.getLogger(ConnectionHandler.class.getName());

    private static Map<Signature, Label>[] signatures;
    private static List<Fingerprint> prints = new LinkedList<Fingerprint>();

    private HashMap<Signature, PcapConnection> connections = new HashMap<Signature, PcapConnection>();

    static {
        signatures = (Map<Signature, Label>[]) new HashMap<?, ?>[getHeaderCount()];
        for (int i = 0; i < signatures.length; i++) {
            signatures[i] = new HashMap<Signature, Label>();
        }

        registerFingerprint(new MtuFingerprint());
        registerFingerprint(new TcpFingerprint());
    }

    public static Signature registerSignature(Signature signature, Label label) {
        Map<Signature, Label> signatures = ConnectionHandler.signatures[label.getType().ordinal()];

        if (!signatures.containsKey(signature)) {
            signatures.put(signature, label);

            return signature;
        }

        throw new IllegalArgumentException("signature doubles " + signatures.get(signature));
    }

    public static void registerP0fFile(File file) throws FileNotFoundException {
        P0fFile p0fFile = new P0fFile(file.getAbsolutePath());

        for (Group group : p0fFile.getGroups()) {
            int groupLine = 1;

            for (Signature signature : group.getSignatures()) {
                try {
                    registerSignature(signature, group.getLabel());
                } catch (IllegalArgumentException e) {
                    logger.warning(group.getLabel() + ", " + groupLine + ". " + e.getMessage());
                }

                groupLine++;
            }
        }

    }

    public static int getFingerprintCount() {
        return prints.size();
    }

    public static void registerFingerprint(Fingerprint fingerprint) {
        prints.add(fingerprint);
    }

    PcapConnection getConnection(Signature session) {
        if (!connections.containsKey(session)) {
            connections.put(session, new PcapConnection(session));
            PcapConnection connection = connections.get(session);

            logger.info("new connection " + session.toString());
            newConnection(connection);

            return connection;
        } else {
            return connections.get(session);
        }
    }

    @Override
    public void newPacket(PcapPacket packet) {
        Signature session = packet.getSession();
        logger.info(packet.toString());

        if (session != null) {
            PcapConnection connection = getConnection(session);

            connection.getTrace().add(packet);

            for (Fingerprint print : prints) {
                if (print.isBound(packet)) {
                    Label label = lookupSignature(print.peer(packet));

                    if (label != null) {
                        connection.addLabel(packet.getDirection(), print, label);

                        logger.info(label.toString());
                    }
                }
            }

            synchronized (connection) {
                connection.notify();
            }
        }
    }

    private Label lookupSignature(Fingerprint.Signature signature) {
        logger.info(signature.toString());

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

    public abstract void newConnection(PcapConnection connection);
}
