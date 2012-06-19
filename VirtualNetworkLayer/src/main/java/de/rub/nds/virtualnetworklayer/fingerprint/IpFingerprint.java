package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.TimeToLive;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.IpHeader;

import java.util.Set;

public abstract class IpFingerprint extends Fingerprint {

    @Override
    public void match(Signature signature, PcapPacket packet) {
        IpHeader ipHeader;

        if (packet.hasHeader(Ip4Header.Id)) {
            ipHeader = matchIp4Header(signature, packet);
            signature.addSign("version", 4);
        } else {
            ipHeader = matchIp6Header(signature, packet);
            signature.addSign("version", 6);
        }

        signature.addSign("timeToLive", new TimeToLive(ipHeader.getHopLimit()));
    }

    private Ip4Header matchIp4Header(Signature signature, PcapPacket packet) {
        Ip4Header ip4Header = packet.getHeader(Ip4Header.Id);
        signature.addSign("optionsLength", ip4Header.getOptionsLength());

        Set<Ip4Header.Flag> flags = ip4Header.getFlags();


        if (flags.contains(Ip4Header.Flag.MBZ)) {
            signature.addQuirk(Quirk.NZ_MBZ);
        }

        if (flags.contains(Ip4Header.Flag.DF)) {
            signature.addQuirk(Quirk.DF);

            if (ip4Header.getId() != 0) {
                signature.addQuirk(Quirk.NZ_ID);
            }

        } else {

            if (ip4Header.getId() == 0) {
                signature.addQuirk(Quirk.ZERO_ID);
            }
        }

        if (ip4Header.getTypeOfService() != 0) {
            signature.addQuirk(Quirk.ECN);
        }

        return ip4Header;
    }

    private IpHeader matchIp6Header(Signature signature, PcapPacket packet) {
        Ip6Header ip6Header = packet.getHeader(Ip6Header.Id);

        signature.addSign("optionsLength", 0);

        if (ip6Header.getTrafficClass() != 0) {
            signature.addQuirk(Quirk.ECN);
        }

        if (ip6Header.getFlowLabel() != 0) {
            signature.addQuirk(Quirk.FLOW);
        }

        return ip6Header;
    }
}
