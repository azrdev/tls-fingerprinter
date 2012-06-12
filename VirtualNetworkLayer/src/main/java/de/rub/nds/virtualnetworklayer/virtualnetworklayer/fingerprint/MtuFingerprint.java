package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.util.Set;

public class MtuFingerprint extends Fingerprint {

    @Override
    public void match(Signature signature, PcapPacket packet) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        int minimalTcpLength;

        if (packet.hasHeader(Ip4Header.Id)) {
            minimalTcpLength = 40;
        } else {
            minimalTcpLength = 60;
        }

        signature.addSign("mtu", tcpHeader.getOption(TcpHeader.Option.MaximumSegmentSize).getValue() + minimalTcpLength);
    }

    @Override
    public boolean isBound(PcapPacket packet) {
        if (packet.hasHeader(TcpHeader.Id)) {
            TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
            Set<TcpHeader.Flag> flags = tcpHeader.getFlags();

            return (flags.contains(TcpHeader.Flag.SYN) ||
                    (flags.contains(TcpHeader.Flag.SYN) && flags.contains(TcpHeader.Flag.ACK)))
                    && tcpHeader.getOptions().contains(TcpHeader.Option.MaximumSegmentSize);

        }

        return false;
    }
}
