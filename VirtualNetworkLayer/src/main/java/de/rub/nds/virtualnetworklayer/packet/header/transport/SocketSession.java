package de.rub.nds.virtualnetworklayer.packet.header.transport;

import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;

import java.util.Arrays;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class SocketSession {
    private byte[] sourceAddress;
    private byte[] destinationAddress;

    private int sourcePort;
    private int destinationPort;

    public SocketSession(byte[] sourceAddress, byte[] destinationAddress, int sourcePort, int destinationPort) {
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
    }

    public Packet.Direction getDirection(PcapPacket packet) {
        Ip ipHeader = (Ip) (packet.hasHeader(Ip4Header.Id) ? packet.getHeader(Ip4Header.Id) : packet.getHeader(Ip6Header.Id));

        if (Arrays.equals(ipHeader.getSourceAddress(), sourceAddress)) {
        	if (packet.hasHeader(TcpHeader.Id)) {
        		TcpHeader tp = packet.getHeader(TcpHeader.Id);
        		if ((tp.getDestinationPort() == destinationPort) && (tp.getSourcePort() == sourcePort)) {
        			return Packet.Direction.Request;
        		}
        	}
        }
        return Packet.Direction.Response;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SocketSession)) {
            return false;
        }

        SocketSession other = (SocketSession) o;

        return (sourcePort == other.sourcePort && destinationPort == other.destinationPort &&
                Arrays.equals(sourceAddress, other.sourceAddress) && Arrays.equals(destinationAddress, other.destinationAddress))
                || (sourcePort == other.destinationPort && destinationPort == other.sourcePort &&
                Arrays.equals(sourceAddress, other.destinationAddress) && Arrays.equals(destinationAddress, other.sourceAddress));
    }

    public byte[] getSourceAddress() {
        return sourceAddress;
    }

    public byte[] getDestinationAddress() {
        return destinationAddress;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    /**
     * Calculate hash code for a socket session.
     * Keep the hash commutative for source{Address, Port} and destination{Address, Port}.
     *
     * @return commutative hash code
     * @see Util#hashCode(Object...)
     */
    @Override
    public int hashCode() {
        int firstGroup = Util.hashCode(Arrays.hashCode(sourceAddress), sourcePort);
        int secondGroup = Util.hashCode(Arrays.hashCode(destinationAddress), destinationPort);

        return firstGroup * secondGroup;
    }

    @Override
    public String toString() {
        return "[" + IpFormatter.toString(sourceAddress) + ", " + sourcePort + " | " + IpFormatter.toString(destinationAddress) + ", " + destinationPort + "]";
    }
}
