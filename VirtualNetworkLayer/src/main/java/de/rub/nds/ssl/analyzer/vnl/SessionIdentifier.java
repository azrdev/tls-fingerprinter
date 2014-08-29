package de.rub.nds.ssl.analyzer.vnl;

import com.google.common.net.InetAddresses;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
                             String serverHostName) {
        setServerTcpPort(serverTcpPort);
        this.serverIPAddress = serverIPAddress;
        this.serverHostName = serverHostName;
    }

    /**
     * deserialize a SessionIdentifier object, see {@link SessionIdentifier#serialize()}
     */
    public SessionIdentifier(String serialized) {
        String[] parts = serialized.split("|");

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
        return result;
    }

    @Override
    public String toString() {
        return String.format("Connection to %s port %d, server name %s",
                IpFormatter.toString(serverIPAddress),
                serverTcpPort,
                serverHostName);
    }

    public String serialize() {
        return String.format("%s|%d|%s",
                Util.ipAddressToString(serverIPAddress),
                serverTcpPort,
                serverHostName);
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
}
