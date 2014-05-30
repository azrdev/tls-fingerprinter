package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * Transport Layer Security Record
 * <p/>
 * For binding to {@link #DefaultPorts} only use {@code new TlsHeader(true)}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Application)
public class TlsHeader extends Header {
    public final static int Id = Headers.Tls.getId();
    public final static Set<Integer> DefaultPorts;

    static {
        //TODO: load from /etc/protocols and/or /etc/services
        DefaultPorts = new HashSet<Integer>();
        DefaultPorts.add(162); //nsiiops
        DefaultPorts.add(443); //https
        DefaultPorts.add(448); //ddm-ssl
        DefaultPorts.add(465); //smtps
        DefaultPorts.add(563); //nntps
        DefaultPorts.add(614); //sshell
        DefaultPorts.add(636); //ldaps
        DefaultPorts.add(989); //ftps-data
        DefaultPorts.add(990); //ftps
        DefaultPorts.add(992); //telnets
        DefaultPorts.add(993); //imaps
        DefaultPorts.add(994); //ircs
        DefaultPorts.add(995); //pop3s
        DefaultPorts.add(5061); //sips
    }

    public static enum ContentType {
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

    public static enum Version {
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

    private boolean bindToDefaultPorts;

    public TlsHeader(boolean bindToDefaultPorts) {
        this.bindToDefaultPorts = bindToDefaultPorts;
    }

    public TlsHeader() {
        this(true);
    }

    public ContentType getContentType() {
        return ContentType.valueOf(getByte(0));
    }

    public Version getVersion() {
        return Version.valueOf(getByte(1), getByte(2));
    }

    @Override
    public int getPayloadLength() {
        return getUShort(3);
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
    	if (previousHeaders.size() > 0) {
    		Header previousHeader = previousHeaders.getLast();

    		if ((previousHeaders.size() > 0) && (previousHeader instanceof TcpHeader)) {
    			TcpHeader header = (TcpHeader) previousHeader;

    			if (bindToDefaultPorts
    					&& !(DefaultPorts.contains(header.getDestinationPort()) || DefaultPorts.contains(header.getSourcePort()))) {
    				return false;
    			}

    			return previousHeader.getPayloadLength() >= getLength() && getContentType() != null && getVersion() != null;
    		} else if ((previousHeaders.size() > 0) && (previousHeader instanceof TlsHeader)) {
    			return getBufferLength() >= getLength() && getContentType() != null && getVersion() != null;
    		}
    	}

        return false;
    }

}
