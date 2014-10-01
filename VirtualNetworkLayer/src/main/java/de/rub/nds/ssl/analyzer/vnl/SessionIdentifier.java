package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;

import java.util.Arrays;

/**
 * Set of attributes defining a unique connection to some server, e.g. corresponding to a
 * particular TLS session.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SessionIdentifier {
    private byte[] serverIPAddress;
    private int serverTcpPort;
    private String serverHostName;

    private Fingerprint clientHelloSignature;

    private static final int MAX_PORT = 65535;

    /**
     * Initializes all attributes with null
     */
    public SessionIdentifier() {}

    /**
     * Initializes all attributes with the given values
     */
    public SessionIdentifier(byte[] serverIPAddress,
                             int serverTcpPort,
                             String serverHostName,
                             Fingerprint clientHelloSignature) {
        setServerTcpPort(serverTcpPort);
        this.serverIPAddress = serverIPAddress;
        this.serverHostName = serverHostName;
        this.clientHelloSignature = clientHelloSignature;
    }

    /**
     * deserialize a SessionIdentifier object, see {@link SessionIdentifier#serialize()}
     */
    public SessionIdentifier(String serialized) {
        String[] parts = serialized.split("\\|");

        if(parts.length > 0)
            serverIPAddress = Util.ipAddressFromString(parts[0]);
        if(parts.length > 1)
            serverTcpPort = Util.readBoundedInteger(parts[1], 0, 65536);
        if(parts.length > 2)
            serverHostName = parts[2];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        SessionIdentifier that = (SessionIdentifier) o;

        if (serverTcpPort != that.serverTcpPort)
            return false;
        if (serverHostName != null ?
                !serverHostName.equals(that.serverHostName) :
                that.serverHostName != null)
            return false;
        if (!Arrays.equals(serverIPAddress, that.serverIPAddress))
            return false;
        if (clientHelloSignature != null ?
                !clientHelloSignature.equals(that.clientHelloSignature) :
                that.clientHelloSignature != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = serverIPAddress != null ?
                Arrays.hashCode(serverIPAddress) : 0;
        result = prime * result + serverTcpPort;
        result = prime * result +
                (serverHostName != null ? serverHostName.hashCode() : 0);
        result = prime * result +
                (clientHelloSignature != null ? clientHelloSignature.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return String.format("Connection to %s port %d, server name %s. ClientHello:\n%s",
                IpFormatter.toString(serverIPAddress),
                serverTcpPort,
                serverHostName,
                clientHelloSignature);
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder();
        sb.append(Util.ipAddressToString(serverIPAddress)).append('|');
        sb.append(serverTcpPort).append('|');
        if(serverHostName != null)
            sb.append(serverHostName);
        sb.append("\n");
        sb.append(Serializer.serializeClientHello(clientHelloSignature));

        return sb.toString();
    }

    public void setServerIPAddress(byte[] serverIPAddress) {
        this.serverIPAddress = serverIPAddress;
    }

    public void setServerTcpPort(int serverTcpPort) {
        if(serverTcpPort > MAX_PORT) {
            throw new IllegalArgumentException("Server port out of range: " + serverTcpPort);
        }
        this.serverTcpPort = serverTcpPort;
    }

    public void setServerHostName(String serverHostName) {
        this.serverHostName = serverHostName;
    }

    public Fingerprint getClientHelloSignature() {
        return clientHelloSignature;
    }

    public void setClientHelloSignature(Fingerprint clientHelloSignature) {
        this.clientHelloSignature = clientHelloSignature;
    }
}
