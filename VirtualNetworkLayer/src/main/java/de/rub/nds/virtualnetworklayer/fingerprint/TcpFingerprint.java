package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.WindowSize;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class TcpFingerprint extends IpFingerprint {
    public static int Id = Fingerprints.Tcp.getId();

    @Override
    public void match(Signature signature, PcapPacket packet, PcapConnection connection) {
        super.match(signature, packet, connection);

        //see p0f: config.h
        signature.setMaximumDistance(35);

        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        List<TcpHeader.Option> optionsLayout = getOptionsLayout(tcpHeader);
        signature.addSign("optionsLayout", optionsLayout);
        signature.hashCode = Util.enumHashCode(optionsLayout);

        int maxiumSegementSize = 0;

        Header.Option option = tcpHeader.getOption(TcpHeader.Option.MaximumSegmentSize);
        if (option != null) {
            maxiumSegementSize = option.getUShort();
        }

        signature.addSign("maximumSegmentSize", maxiumSegementSize);
        signature.addSign("windowSize", getWindowSize(maxiumSegementSize, packet, connection));


        option = tcpHeader.getOption(TcpHeader.Option.WindowScale);
        if (option != null) {
            signature.addSign("windowScale", option.getUByte());

            if (option.getUByte() > 14) {
                signature.addQuirk(Quirk.OPT_EXWS);
            }
        }

        option = tcpHeader.getOption(TcpHeader.Option.EndOfOptionsList);
        if (option != null) {
            if (!new String(option.getData().array()).trim().isEmpty()) {
                signature.addQuirk(Quirk.OPT_EOL_NZ);
            }
        }

        option = tcpHeader.getOption(TcpHeader.Option.TimeStamp);
        if (option != null) {
            if (option.getData().getInt() == 0) {
                signature.addQuirk(Quirk.OPT_ZERO_TS1);
            }

            if (!tcpHeader.getFlags().contains(TcpHeader.Flag.ACK) && option.getData().getInt(4) != 0) {
                signature.addQuirk(Quirk.OPT_NZ_TS2);
            }
        }

        signature.addSign("payloadClass", getPayloadClass(tcpHeader));
        signature.addSign("direction", packet.getDirection());

        if (tcpHeader.getSequenceNumber() == 0) {
            signature.addQuirk(Quirk.ZERO_SEQ);
        }

        addFlags(signature, tcpHeader, tcpHeader.getFlags());
    }

    private void addFlags(Signature signature, TcpHeader tcpHeader, Set<TcpHeader.Flag> flags) {
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
    }

    private List<TcpHeader.Option> getOptionsLayout(TcpHeader tcpHeader) {
        List<TcpHeader.Option> optionsLayout = new LinkedList<TcpHeader.Option>();

        for (Header.Option<TcpHeader.Option> option : tcpHeader.getOptions()) {
            optionsLayout.add(option.getType());
        }

        return optionsLayout;
    }

    private TCPSignature.PayloadClass getPayloadClass(TcpHeader tcpHeader) {
        if (tcpHeader.getPayloadLength() > 0) {
            return TCPSignature.PayloadClass.Positive;
        }

        return TCPSignature.PayloadClass.Zero;
    }

    /**
     * Figure out if window size is a multiplier of MSS or MTU. We don't take window
     * scaling into account, because neither do TCP stack developers.
     *
     * @param packet
     * @param connection
     * @return return window size typed with mtu or mss, otherwise normal
     */
    private WindowSize getWindowSize(int maxiumSegementSize, PcapPacket packet, PcapConnection connection) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
        WindowSize size = new WindowSize(tcpHeader.getWindowSize(), WindowSize.Type.Normal);

        List<Integer> divisors = new ArrayList<Integer>();
        divisors.add(maxiumSegementSize);

        /* Some systems will sometimes subtract 12 bytes when timestamps are in use. */
        divisors.add(maxiumSegementSize - 12);

        /* Some systems use MTU on the wrong interface, so let's check for the most
          common case. */
        divisors.add(1500 - MtuFingerprint.getMinimalTcpLength(packet));
        divisors.add(1500 - MtuFingerprint.getMinimalTcpLength(packet) - 12);

        /* On SYN+ACKs, some systems use of the peer: */
        Fingerprint.Signature tcpSignature = connection.getSignature(packet.getDirection().flip(), TcpFingerprint.Id);
        if (tcpSignature != null) {
            divisors.add((Integer) tcpSignature.getSign("maximumSegmentSize"));
            divisors.add((Integer) tcpSignature.getSign("maximumSegmentSize") - 12);
        }

        if (size.modulo(divisors)) {
            return new WindowSize(size.getSize(), WindowSize.Type.Mss);
        }

        /* Some systems use MTU instead of MSS: */
        divisors = new ArrayList<Integer>();
        Fingerprint.Signature mtuSignature = connection.getSignature(packet.getDirection(), MtuFingerprint.Id);
        if (mtuSignature != null) {
            divisors.add((Integer) mtuSignature.getSign("mtu"));
            divisors.add(maxiumSegementSize + packet.getHeader(Headers.Tcp).getPayloadOffset());
            divisors.add(1500);
        }

        if (size.modulo(divisors)) {
            return new WindowSize(size.getSize(), WindowSize.Type.Mtu);
        }

        return size;
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
                    (flags.contains(TcpHeader.Flag.SYN) && flags.contains(TcpHeader.Flag.ACK)));

        }

        return false;
    }

    @Override
    public int getId() {
        return Id;
    }

}
