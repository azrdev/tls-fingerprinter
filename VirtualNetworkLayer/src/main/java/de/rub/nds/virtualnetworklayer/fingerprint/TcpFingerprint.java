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
    public static int Id = 1;

    private List<TcpHeader.Option> optionsLayout;
    private int maxiumSegementSize;
    private int windowScale;

    @Override
    public void match(Signature signature, PcapPacket packet) {
        super.match(signature, packet);
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        signature.addSign("optionsLayout", tcpHeader.getOptions());
        maxiumSegementSize = (int) tcpHeader.getOption(TcpHeader.Option.MaximumSegmentSize).getValue();
        signature.addSign("maximumSegmentSize", maxiumSegementSize);

        windowScale = (int) tcpHeader.getOption(TcpHeader.Option.WindowScale).getValue();
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
        WindowSize.Type type = WindowSize.Type.Normal;
        int size = tcpHeader.getWindowSize();

        if (maxiumSegementSize > 0 && size % maxiumSegementSize == 0) {
            type = WindowSize.Type.Mss;
            size /= maxiumSegementSize;
        }

        return new WindowSize(size, type);
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

    @Override
    public int getId() {
        return Id;
    }

}
