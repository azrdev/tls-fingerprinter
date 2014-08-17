package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.virtualnetworklayer.fingerprint.MtuFingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.TcpFingerprint;

import java.util.Set;

/**
 * Collection of Fingerprint.Signature instances
 * <p>
 * TODO: change to be Map < Type, Fingerprint.Signature > when Fingerprint classes are unified
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class TLSFingerprint {

    // static Fingerprint instances for signature creation

    private static ClientHelloFingerprint clientHelloFingerprint =
            new ClientHelloFingerprint();
    private static ServerHelloFingerprint serverHelloFingerprint =
            new ServerHelloFingerprint();
    private static TcpFingerprint serverTcpFingerprint = new TcpFingerprint();
    private static MtuFingerprint serverMtuFingerprint = new MtuFingerprint();

    // non-static Signature instances

    private Fingerprint.Signature clientHelloSignature;
    private Fingerprint.Signature serverHelloSignature;
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
        clientHelloSignature = clientHelloFingerprint.createSignature(connection);
        serverHelloSignature = serverHelloFingerprint.createSignature(connection);

        serverTcpSignature = connection.getServerTcpSignature();
        serverMtuSignature = connection.getServerMtuSignature();
    }

    public Fingerprint.Signature getClientHelloSignature() {
        return clientHelloSignature;
    }

    public Fingerprint.Signature getServerHelloSignature() {
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
}