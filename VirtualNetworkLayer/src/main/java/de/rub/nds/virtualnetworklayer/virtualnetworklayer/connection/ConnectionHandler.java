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
    private final static Logger logger = Logger.getLogger(ConnectionHandler.class.getName());

    private static Map<Signature, Label> specificSignatures = new HashMap<Signature, Label>();
    private static Map<Signature, Label> genericSignatures = new HashMap<Signature, Label>();
    //private static Map<Signature, Label>[] signatures = (Map<Signature, Label>[]) new HashMap<?,?>[2];

    private static List<Fingerprint> prints = new LinkedList<Fingerprint>();
    private static HashMap<Signature, PcapConnection> connections = new HashMap<Signature, PcapConnection>();

    static {
        prints.add(new MtuFingerprint());
        prints.add(new TcpFingerprint());
    }

    public static Signature registerSignature(Signature signature, Label label) {
        Map<Signature, Label> signatures;

        if (label.getType() == Label.Type.Specific) {
            signatures = specificSignatures;
        } else {
            signatures = genericSignatures;
        }

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

    public static void registerFingerprint(Fingerprint fingerprint) {
        prints.add(fingerprint);
    }

    private PcapConnection newConnection(Signature session, PcapPacket packet) {
        connections.put(session, new PcapConnection());

        PcapConnection connection = connections.get(session);
        connection.getTrace().add(packet);

        newConnection(connection);

        return connection;
    }

    @Override
    public void newPacket(PcapPacket packet) {
        Signature session = packet.getSession();
        PcapConnection connection = null;
        if (session != null) {
            if (!connections.containsKey(session)) {
                connection = newConnection(session, packet);
            } else {
                connection = connections.get(session);
                connection.getTrace().add(packet);
            }
        }

        for (Fingerprint print : prints) {
            if (print.isBound(packet)) {
                Label label = lookupSignature(print.peer(packet));

                if (label != null) {
                    connection.addLabel(label);

                    logger.info(label.toString());
                }
            }
        }
    }

    private Label lookupSignature(Fingerprint.Signature signature) {
        logger.info(signature.toString());

        if (specificSignatures.containsKey(signature)) {
            return specificSignatures.get(signature);
        }

        if (genericSignatures.containsKey(signature)) {
            return genericSignatures.get(signature);
        }

        return null;
    }

    public abstract void newConnection(PcapConnection connection);
}
