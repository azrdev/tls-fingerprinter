package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import com.google.common.base.Joiner;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;
import org.apache.log4j.Logger;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Collection of Fingerprint signatures identifying a TLS endpoint
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class TLSFingerprint {
    private static final Logger logger = Logger.getLogger(TLSFingerprint.class);

    // static Fingerprint instances for signature creation
    private static TcpFingerprint serverTcpFingerprint = new TcpFingerprint();
    private static MtuFingerprint serverMtuFingerprint = new MtuFingerprint();

    // non-static Signature instances
    private HandshakeFingerprint handshakeSignature;
    private ServerHelloFingerprint serverHelloSignature;
    private de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature serverTcpSignature;
    private de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature serverMtuSignature;

    public <T extends de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint>
    TLSFingerprint(HandshakeFingerprint handshakeSignature,
                   ServerHelloFingerprint serverHelloSignature,
                   T.Signature serverTcpSignature,
                   T.Signature serverMtuSignature) {
        this.handshakeSignature = handshakeSignature;
        this.serverHelloSignature = serverHelloSignature;
        this.serverTcpSignature = serverTcpSignature;
        this.serverMtuSignature = serverMtuSignature;
    }

    /**
     * initialize all signatures from connection
     */
    public TLSFingerprint(Connection connection) {
        try {
            serverHelloSignature = ServerHelloFingerprint.create(connection);
        } catch(RuntimeException e) {
            logger.debug("Error creating ServerHelloFingerprint: " + e);
        }
        handshakeSignature = HandshakeFingerprint.create(connection.getFrameList());

        serverTcpSignature = connection.getServerTcpSignature();
        serverMtuSignature = connection.getServerMtuSignature();
    }

    public HandshakeFingerprint getHandshakeSignature() {
        return handshakeSignature;
    }

    public ServerHelloFingerprint getServerHelloSignature() {
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
        if (o == null || !(o instanceof TLSFingerprint))
            return false;

        TLSFingerprint that = (TLSFingerprint) o;

        if (handshakeSignature != null?
                !handshakeSignature.equals(that.handshakeSignature) :
                that.handshakeSignature != null)
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
        int result = 0;
        result = prime * result +
                (handshakeSignature != null ? handshakeSignature.hashCode() : 0);
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
        sb.append("\nHandshake: {\n").append(handshakeSignature).append("\n}");
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
    public String differenceString(TLSFingerprint other, String otherName) {
        return getClass().getSimpleName() + " difference to " + otherName + ":\n" +
                Joiner.on("\n").join(difference(other));
    }

    /**
     * @return List of Strings describing all the changed signs w.r.t. <code>other</code>
     */
    public List<String> difference(TLSFingerprint other) {
        List<String> differences = new LinkedList<>();

        for(Map.Entry<String, SignatureDifference.SignDifference> difference :
                differenceMap(other).entries()) {
            differences.add(difference.getKey() + "." + difference.getValue());
        }


        return differences;
    }

    public SetMultimap<String, SignatureDifference.SignDifference>
    differenceMap(TLSFingerprint other) {
        SetMultimap<String, SignatureDifference.SignDifference> differences =
                HashMultimap.create();
        Set<SignatureDifference.SignDifference> differenceSet;

        differenceSet = SignatureDifference.fromGenericFingerprints(handshakeSignature,
                other.getHandshakeSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            differences.put("Handshake", d);
        }

        differenceSet = SignatureDifference.fromGenericFingerprints(serverHelloSignature,
                other.getServerHelloSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            differences.put("ServerHello", d);
        }

        differenceSet = SignatureDifference.fromVnlFingerprints(serverTcpSignature,
                other.getServerTcpSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            differences.put("ServerTCP", d);
        }

        differenceSet = SignatureDifference.fromVnlFingerprints(serverMtuSignature,
                other.getServerMtuSignature()).getDifferences();
        for(SignatureDifference.SignDifference d : differenceSet) {
            differences.put("ServerMTU", d);
        }

        return differences;
    }

    public String serialize() {
        return Serializer.serialize(this);
    }
}