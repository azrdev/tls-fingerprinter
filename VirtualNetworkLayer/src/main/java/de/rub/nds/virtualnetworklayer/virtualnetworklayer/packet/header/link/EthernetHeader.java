package de.rub.nds.virtualnetworklayer.packet.header.link;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.util.List;

public class EthernetHeader extends Header {
    public static int Id = 1;

    public static enum Type {
        Ip4(0x800),
        Ip6(0x86DD),
        Arp(0x0806),
        RArp(0x8035);

        private int id;

        private Type(int id) {
            this.id = id;
        }

        public int getId() {
            return this.id;
        }

        public static Type valueOf(int type) {
            for (Type t : values()) {
                if (t.id == type) {
                    return t;
                }
            }

            return null;
        }

    }

    public byte[] getDestinationMac() {
        return getBytes(0, 8);
    }

    public byte[] getSourceMac() {
        return getBytes(8, 8);
    }

    public Type getType() {
        return Type.valueOf(getUShort(12));
    }

    @Override
    public int getLength() {
        return 14;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(List<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        return previousHeaders.isEmpty() && dataLinkType == Pcap.DataLinkType.Ethernet;
    }
}
