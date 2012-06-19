package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.util.LinkedList;

public class TlsHeader extends Header {
    public static int Id = 5;

    public enum ContentType {
        ChangeCipherSpec(20),
        Alert(21),
        Handshake(22),
        Application(23);

        private int type;

        private ContentType(int type) {
            this.type = type;
        }

        public static ContentType valueOf(int type) {
            for (ContentType content : values()) {
                if (type == content.type) {
                    return content;
                }
            }

            return null;
        }
    }

    public enum Version {
        SSL3_0(3, 0),
        TLS1_0(3, 1),
        TLS1_1(3, 2),
        TLS1_2(3, 2);

        private int major;
        private int minor;

        private Version(int major, int minor) {
            this.major = major;
            this.minor = minor;
        }

        public static Version valueOf(int major, int minor) {
            for (Version version : values()) {
                if (major == version.major && minor == version.minor) {
                    return version;
                }
            }

            return null;
        }
    }

    public ContentType getContentType() {
        return ContentType.valueOf(getByte(0));
    }

    public Version getVersion() {
        return Version.valueOf(getByte(1), getByte(2));
    }

    @Override
    public int getPayloadLength() {
        return getShort(3);
    }

    @Override
    public int getLength() {
        return 5;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        Header previousHeader = previousHeaders.getLast();

        if (previousHeader instanceof TcpHeader) {
            TcpHeader header = (TcpHeader) previousHeader;
            //TODO
            return (header.getDestinationPort() == 443 || header.getSourcePort() == 443) &&
                    getContentType() != null && getVersion() != null;
        } else if (previousHeader instanceof TlsHeader) {
            return getContentType() != null && getVersion() != null;
        }

        return false;
    }

}
