package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.WindowSize;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.List;
import java.util.Set;

public class TcpFingerprint extends IpFingerprint {

    private List<TcpHeader.Option> optionsLayout;
    private long maxiumSegementSize;
    private long windowScale;

    @Override
    public void match(Signature signature, PcapPacket packet) {
        super.match(signature, packet);
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        signature.addSign("optionsLayout", tcpHeader.getOptions());
        maxiumSegementSize = tcpHeader.getOption(TcpHeader.Option.MaximumSegmentSize).getValue();
        signature.addSign("maximumSegmentSize", maxiumSegementSize);

        windowScale = tcpHeader.getOption(TcpHeader.Option.WindowScale).getValue();
        signature.addSign("windowScale", windowScale);

        signature.addSign("windowSize", getWindowSize(tcpHeader));
        signature.addSign("payloadClass", getPayloadClass(tcpHeader));

        signature.addSign("direction", packet.getDirection());

        if (windowScale > 14) {
            signature.addQuirk(Quirk.OPT_EXWS);
        }

        if (tcpHeader.getPayloadLength() > 0) {
            signature.addQuirk(Quirk.OPT_EOL_NZ);
        }

        if (tcpHeader.getSequenceNumber() == 0) {
            signature.addQuirk(Quirk.ZERO_SEQ);
        }

        Set<TcpHeader.Flag> flags = tcpHeader.getFlags();
        if (flags.contains(TcpHeader.Flag.URG)) {
            signature.addQuirk(Quirk.URG);
        } else {
            if (tcpHeader.getUrgentPointer() != 0) {
                signature.addQuirk(Quirk.NZ_URG);
            }
        }

        if (flags.contains(TcpHeader.Flag.PSH)) {
            signature.addQuirk(Quirk.PUSH);
        }

        if (flags.contains(TcpHeader.Flag.ECE) || flags.contains(TcpHeader.Flag.CWR)) {
            signature.addQuirk(Quirk.ECN);
        }

        if (flags.contains(TcpHeader.Flag.ACK)) {
            if (tcpHeader.getAcknowledgmentNumber() == 0) {
                signature.addQuirk(Quirk.ZERO_ACK);
            }
        } else {
            if (tcpHeader.getAcknowledgmentNumber() != 0 && !flags.contains(TcpHeader.Flag.RST)) {
                signature.addQuirk(Quirk.NZ_ACK);
            }
        }

        signature.hashCode = Util.enumHashCode(tcpHeader.getOptions());
    }

    private TCPSignature.PayloadClass getPayloadClass(TcpHeader tcpHeader) {
        if (tcpHeader.getPayloadLength() > 0) {
            return TCPSignature.PayloadClass.Positive;
        }

        return TCPSignature.PayloadClass.Zero;
    }

    private WindowSize getWindowSize(TcpHeader tcpHeader) {
        WindowSize windowSize = WindowSize.Normal;

        if (maxiumSegementSize > 0 && tcpHeader.getWindowSize() % maxiumSegementSize == 0) {
            windowSize = WindowSize.Mss;
        }

        windowSize.setSize(tcpHeader.getWindowSize());

        return windowSize;
    }

    @Override
    public boolean isBound(PcapPacket packet) {
        if (packet.hasHeader(TcpHeader.Id)) {
            TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
            Set<TcpHeader.Flag> flags = tcpHeader.getFlags();

            return (flags.contains(TcpHeader.Flag.SYN) ||
                    (flags.contains(TcpHeader.Flag.SYN) && flags.contains(TcpHeader.Flag.ACK)));

        }

        return false;
    }

}
