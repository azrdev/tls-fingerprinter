package de.rub.nds.virtualnetworklayer.packet.header.transport;


import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.Session;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip6Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Transmission Control Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Transport)
public class TcpHeader extends Header implements Session, Port {
    public final static int Id = Headers.Tcp.getId();

    public static enum Flag {
        FIN(0x01),
        SYN(0x02),
        RST(0x04),
        PSH(0x08),
        ACK(0x10),
        URG(0x20),
        ECE(0x40),
        CWR(0x80);

        private int position;

        private Flag(int position) {
            this.position = position;
        }
    }

    public static enum Option {
        EndOfOptionsList(0),
        NoOp(1),
        MaximumSegmentSize(2),
        WindowScale(3),
        SackPermitted(4),
        Sack(5),
        Echo(6),
        EchoReply(7),
        TimeStamp(8),
        PartialOrderConnectionPermitted(9),
        PartialOrderConnection(10),
        AlternateChecksumRequest(14),
        AlternateChecksum(15);

        private int id;

        private Option(int id) {
            this.id = id;
        }

        public static Option valueOf(int id) {
            for (Option option : values()) {
                if (option.id == id) {
                    return option;
                }
            }

            return null;
        }
    }

    private List<Header.Option<Option>> options;
    private Set<Flag> flags;

    public int getSourcePort() {
        return getUShort(0);
    }

    public int getDestinationPort() {
        return getUShort(2);
    }

    public long getSequenceNumber() {
        return getUInteger(4);
    }

    public long getAcknowledgmentNumber() {
        return getUInteger(8);
    }

    public int getReserved() {
        return getSecondNibble(12) >> 1;
    }

    public int getDataOffset() {
        return getFirstNibble(12);
    }

    public Set<Flag> getFlags() {
        if (flags == null) {
            flags = EnumSet.noneOf(TcpHeader.Flag.class);
            int mask = getByte(13);

            for (Flag flag : Flag.values()) {
                if ((mask & flag.position) == flag.position) {
                    flags.add(flag);
                }
            }
        }
        return flags;
    }

    public int getWindowSize() {
        return getUShort(14);
    }

    public int getChecksum() {
        return getUShort(16);
    }

    public int getUrgentPointer() {
        return getUShort(18);
    }

    @Override
    public int getLength() {
        return getDataOffset() * 4;
    }

    public List<Header.Option<Option>> getOptions() {
        if (options == null) {
            options = new LinkedList<Header.Option<Option>>();

            for (int i = 20; i < getLength(); i++) {
                Option option = Option.valueOf(getUByte(i));
                int length = 1;
                byte[] data = null;

                switch (option) {
                    case NoOp:
                        length = 1;
                        break;
                    case EndOfOptionsList:
                        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
                        byteBuffer.putInt(getLength() - i - 1);
                        data = byteBuffer.array();

                        i = getLength();
                        break;

                    default:
                        length = getUByte(i + 1);
                        if (length > 2) {
                            data = getBytes(i + 2, length - 2);
                        }

                        i += length - 1;
                }

                options.add(new Header.Option<Option>(option, length, data));
            }
        }

        return options;
    }

    public Header.Option<TcpHeader.Option> getOption(Option option) {
        for (Header.Option<Option> o : getOptions()) {
            if (o.getType() == option) {
                return o;
            }
        }

        return null;
    }

    public boolean hasOption(Option option) {
        return getOption(option) != null;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof Ip) {
            Ip header = (Ip) previousHeaders.getLast();

            return header.getNextHeader() == Ip.Protocol.Tcp;
        }

        return false;
    }

    public Long getNextSequenceNumber() {
        if (getFlags().contains(Flag.SYN)) {
            return getSequenceNumber() + 1;
        } else {
            return getSequenceNumber() + getPayloadLength();
        }
    }

    @Override
    public SocketSession getSession(PcapPacket packet) {
        Ip ipHeader = (Ip) (packet.hasHeader(Ip4Header.Id) ? packet.getHeader(Ip4Header.Id) : packet.getHeader(Ip6Header.Id));

        return new SocketSession(ipHeader.getSourceAddress(), ipHeader.getDestinationAddress(),
                getSourcePort(), getDestinationPort());
    }

}
