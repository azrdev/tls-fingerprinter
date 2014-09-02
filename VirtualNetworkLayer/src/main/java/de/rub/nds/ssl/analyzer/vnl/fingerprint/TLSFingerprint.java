package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import org.apache.log4j.Logger;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Collection of Fingerprint signatures identifying a TLS endpoint
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class TLSFingerprint {
    private Logger logger = Logger.getLogger(getClass());

    // static Fingerprint instances for signature creation
    private static TcpFingerprint serverTcpFingerprint = new TcpFingerprint();
    private static MtuFingerprint serverMtuFingerprint = new MtuFingerprint();

    // non-static Signature instances

    private Fingerprint clientHelloSignature;
    private Fingerprint serverHelloSignature;
    private de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature serverTcpSignature;
    private de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature serverMtuSignature;

    /**
     * Identifiers to use in a TLSFingerprint
     *
     * TODO: use as key in Map<Type, Fingerprint.Signature> when Fingerprint classes are unified
     *
     * @author jBiegert azrdev@qrdn.de
     */
    /*
    public enum Type {
        CLIENT_TLS_HELLO,
        SERVER_TLS_HELLO,
        SERVER_TCP,
        SERVER_MTU,
    }
    */

    public TLSFingerprint(Connection connection) {
        try {
            clientHelloSignature = new ClientHelloFingerprint(connection);
        } catch(RuntimeException e) {
            logger.debug("Error creating ClientHelloFingerprint: " + e);
        }
        try {
            serverHelloSignature = new ServerHelloFingerprint(connection);
        } catch(RuntimeException e) {
            logger.debug("Error creating ClientHelloFingerprint: " + e);
        }

        serverTcpSignature = connection.getServerTcpSignature();
        serverMtuSignature = connection.getServerMtuSignature();
    }

    public TLSFingerprint(String serialized) {
        deserialize(serialized);
    }

    public Fingerprint getClientHelloSignature() {
        return clientHelloSignature;
    }

    public Fingerprint getServerHelloSignature() {
        return serverHelloSignature;
    }

    public de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature getServerTcpSignature() {
        return serverTcpSignature;
    }

    public de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature getServerMtuSignature() {
        return serverMtuSignature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        TLSFingerprint that = (TLSFingerprint) o;

        if (clientHelloSignature != null ?
                !clientHelloSignature.equals(that.clientHelloSignature) :
                that.clientHelloSignature != null)
            return false;
        if (serverHelloSignature != null ?
                !serverHelloSignature.equals(that.serverHelloSignature) :
                that.serverHelloSignature != null)
            return false;
        if (serverMtuSignature != null ?
                !serverMtuSignature.equals(that.serverMtuSignature) :
                that.serverMtuSignature != null)
            return false;
        if (serverTcpSignature != null ?
                !serverTcpSignature.equals(that.serverTcpSignature) :
                that.serverTcpSignature != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = clientHelloSignature != null ? clientHelloSignature.hashCode() : 0;
        result = prime * result +
                (serverHelloSignature != null ? serverHelloSignature.hashCode() : 0);
        result = prime * result +
                (serverTcpSignature != null ? serverTcpSignature.hashCode() : 0);
        result = prime * result +
                (serverMtuSignature != null ? serverMtuSignature.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TLSFingerprint: {");
        sb.append("\nClient Hello: {\n").append(clientHelloSignature).append("\n}");
        sb.append("\nServer Hello: {\n").append(serverHelloSignature).append("\n}");
        sb.append("\nServer TCP: {\n").append(serverTcpSignature).append("\n}");
        sb.append("\nServer MTU: {\n").append(serverMtuSignature).append("\n}");
        sb.append("\n}");
        return sb.toString();
    }

    /**
     * @return a String representation of everything that has changed w.r.t. other
     * @param otherName text to represent other
     */
    public String difference(TLSFingerprint other, String otherName) {
        StringBuilder sb = new StringBuilder(
                getClass().getSimpleName() + " difference to " + otherName + ":\n");

        Set<SignatureDifference.SignDifference> differenceSet =
            SignatureDifference.fromGenericFingerprints(clientHelloSignature,
                    other.getClientHelloSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            sb.append("ClientHello.").append(d).append("\n");
        }

        differenceSet = SignatureDifference.fromGenericFingerprints(serverHelloSignature,
                other.getServerHelloSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            sb.append("ServerHello.").append(d).append("\n");
        }

        differenceSet = SignatureDifference.fromVnlFingerprints(serverTcpSignature,
                other.getServerTcpSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            sb.append("ServerTCP.").append(d).append("\n");
        }

        differenceSet = SignatureDifference.fromVnlFingerprints(serverMtuSignature,
                other.getServerMtuSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            sb.append("ServerMTU.").append(d).append("\n");
        }

        return sb.toString();
    }

    private enum FingerprintId {
        ClientHello("ClientHello"),
        ServerHello("ServerHello"),
        ServerTcp("ServerTCP"),
        ServerMtu("ServerMTU");

        public final String id;
        public final Pattern pattern;
        FingerprintId(String id) {
            this.id = id;
            pattern = Pattern.compile(id, Pattern.LITERAL | Pattern.CASE_INSENSITIVE);
        }
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder();

        if(clientHelloSignature != null) {
            sb.append("\t").append(FingerprintId.ClientHello.id).append(": ");
            sb.append(clientHelloSignature.serialize()).append('\n');
        }

        if(serverHelloSignature != null) {
            sb.append("\t").append(FingerprintId.ServerHello.id).append(": ");
            sb.append(serverHelloSignature.serialize()).append('\n');
        }

        if(serverTcpSignature != null) {
            sb.append("\t").append(FingerprintId.ServerTcp.id).append(": ");
            sb.append(TCPSignature.writeToString(serverTcpSignature)).append("\n");
        }

        if(serverMtuSignature != null) {
            sb.append("\t").append(FingerprintId.ServerMtu.id).append(": ");
            sb.append(MTUSignature.writeToString(serverMtuSignature)).append("\n");
        }

        return sb.toString();
    }

    private void deserialize(String serialized) {
        for(String signature: serialized.split("\n")) {
            if(signature.trim().isEmpty())
                continue;

            if(! signature.startsWith("\t")) {
                logger.warn("Unknown fingerprint component: " + signature);
                continue;
            }

            try {
                String[] line = signature.trim().split("\\s", 2);
                if(FingerprintId.ClientHello.pattern.matcher(line[0]).lookingAt()) {
                    clientHelloSignature = new ClientHelloFingerprint(line[1]);
                } else if (FingerprintId.ServerHello.pattern.matcher(line[0]).lookingAt()) {
                    serverHelloSignature = new ServerHelloFingerprint(line[1]);
                } else if (FingerprintId.ServerTcp.pattern.matcher(line[0]).lookingAt()) {
                    serverTcpSignature = new TCPSignature(line[1]);
                } else if (FingerprintId.ServerMtu.pattern.matcher(line[0]).lookingAt()) {
                    serverMtuSignature = new MTUSignature(line[1]);
                }
            } catch(IllegalArgumentException|NullPointerException e) {
                logger.debug("Error decoding signature " + signature);
                logger.trace("Caused by " + e, e);
                continue;
            }
        }
    }
}