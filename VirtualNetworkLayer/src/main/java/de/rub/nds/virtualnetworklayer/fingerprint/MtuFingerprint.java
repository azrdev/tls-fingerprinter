package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.util.Set;

/**
 * This class represents a mtu fingerprint.
 * <p/>
 * Many operating systems derive the maximum segment size specified in TCP options
 * from the mtu of their network interface; that value, in turn, normally depends
 * on the design of the link-layer protocol.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class MtuFingerprint extends Fingerprint {
    public static int Id = Fingerprints.Mtu.getId();

    @Override
    public void match(Signature signature, PcapPacket packet, PcapConnection connection) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        int mss = tcpHeader.getOption(TcpHeader.Option.MaximumSegmentSize).getUShort();
        signature.addSign("mtu", mss + getMinimalTcpLength(packet));
    }

    /**
     * p0f uses minimal tcp length in p0f.fp for normalization.
     *
     * @param packet
     * @return minimal offset of tcp payload
     */
    public static int getMinimalTcpLength(PcapPacket packet) {
        if (packet.hasHeader(Ip4Header.Id)) {
            return 40;
        } else {
            return 60;
        }
    }

    /**
     * Only fingerprint SYN or SYN+ACK.
     */
    @Override
    public boolean isBound(PcapPacket packet) {
        if (packet.hasHeader(TcpHeader.Id)) {
            TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
            Set<TcpHeader.Flag> flags = tcpHeader.getFlags();

            return (flags.contains(TcpHeader.Flag.SYN) ||
                    (flags.contains(TcpHeader.Flag.SYN) && flags.contains(TcpHeader.Flag.ACK)))
                    && tcpHeader.hasOption(TcpHeader.Option.MaximumSegmentSize);

        }

        return false;
    }

    @Override
    public int getId() {
        return Id;
    }
}
