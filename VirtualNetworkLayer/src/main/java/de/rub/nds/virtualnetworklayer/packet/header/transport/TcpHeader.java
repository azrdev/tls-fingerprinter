package de.rub.nds.virtualnetworklayer.packet.header.transport;


import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.Session;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.IpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.Signature;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.nio.ByteBuffer;
import java.util.*;

public class TcpHeader extends Header implements Session {
    public static int Id = 3;

    public enum Flag {
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

    public enum Option {
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
        private int length;
        private byte[] data;


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

        public byte[] getData() {
            return data;
        }

        public Option setValue(int value) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(value);
            setData(byteBuffer.array());

            return this;
        }

        public long getValue() {
            long value = 0;

            if (data != null) {
                for (int i = 0; i < data.length; i++) {
                    value = (value << 8) + (data[i] & 0xff);
                }
            }

            return value;
        }

        public void setData(byte[] data) {
            this.data = data;
        }
    }

    public static class Session extends Signature {
        private byte[] sourceAddress;
        private byte[] destinationAddress;

        private int sourcePort;
        private int destinationPort;

        public Session(byte[] sourceAddress, byte[] destinationAddress, int sourcePort, int destinationPort) {
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Session)) {
                return false;
            }

            Session other = (Session) o;

            return (sourcePort == other.sourcePort && destinationPort == other.destinationPort &&
                    Arrays.equals(sourceAddress, other.sourceAddress) && Arrays.equals(destinationAddress, other.destinationAddress))
                    || (sourcePort == other.destinationPort && destinationPort == other.sourcePort &&
                    Arrays.equals(sourceAddress, other.destinationAddress) && Arrays.equals(destinationAddress, other.sourceAddress));
        }

        public byte[] getSourceAddress() {
            return sourceAddress;
        }

        public byte[] getDestinationAddress() {
            return destinationAddress;
        }

        public int getSourcePort() {
            return sourcePort;
        }

        public int getDestinationPort() {
            return destinationPort;
        }

        @Override
        public int hashCode() {
            int firstGroup = Util.hashCode(Arrays.hashCode(sourceAddress), sourcePort);
            int secondGroup = Util.hashCode(Arrays.hashCode(destinationAddress), destinationPort);

            return firstGroup * secondGroup;
        }

        @Override
        public String toString() {
            return "[" + Util.toIp4String(sourceAddress) + ", " + sourcePort + " | " + Util.toIp4String(destinationAddress) + ", " + destinationPort + "]";
        }
    }

    public static class SequenceComparator implements Comparator<PcapPacket> {
        private long initalSequenceNumber;
        private int requestPort;
        private byte[] requestAddress;


        public SequenceComparator(PcapPacket pcapPacket) {
            TcpHeader tcpHeader = pcapPacket.getHeader(Id);
            initalSequenceNumber = tcpHeader.getSequenceNumber();
            requestPort = tcpHeader.getSourcePort();

            Ip4Header ip4Header = pcapPacket.getHeader(Ip4Header.Id);
            requestAddress = ip4Header.getSourceAddress();
        }

        public Packet.Direction getDirection(PcapPacket pcapPacket) {
            TcpHeader tcpHeader = pcapPacket.getHeader(Id);
            Ip4Header ip4Header = pcapPacket.getHeader(Ip4Header.Id);

            if (tcpHeader.getSourcePort() == requestPort &&
                    Arrays.equals(ip4Header.getSourceAddress(), requestAddress)) {

                return Packet.Direction.Request;
            } else {
                return Packet.Direction.Response;
            }

        }

        @Override
        public int compare(PcapPacket pcapPacket, PcapPacket pcapPacket1) {
            TcpHeader tcpHeader = pcapPacket.getHeader(Id);
            TcpHeader tcpHeader1 = pcapPacket1.getHeader(Id);

            return (int) (tcpHeader1.getSequenceNumber() % initalSequenceNumber -
                    tcpHeader.getSequenceNumber() % initalSequenceNumber);
        }
    }

    private List<Option> options;

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
        Set<Flag> flags = EnumSet.noneOf(TcpHeader.Flag.class);
        int mask = getByte(13);

        for (Flag flag : Flag.values()) {
            if ((mask & flag.position) == flag.position) {
                flags.add(flag);
            }
        }

        return flags;
    }

    public int getWindowSize() {
        return getUShort(14);
    }

    public int getChecksum() {
        return getShort(16);
    }

    public int getUrgentPointer() {
        return getShort(18);
    }

    @Override
    public int getLength() {
        return getDataOffset() * 4;
    }

    public List<Option> getOptions() {
        if (options == null) {
            options = new LinkedList<Option>();

            for (int i = 20; i < getLength(); i++) {
                Option option = Option.valueOf(getUByte(i));

                int length;
                switch (option) {
                    case NoOp:
                        length = 1;
                        break;

                    case EndOfOptionsList:
                        option.setValue(getLength() - i - 1);
                        i = getLength();
                        break;

                    default:
                        length = getUByte(i + 1);
                        if (length > 2) {
                            option.setData(getBytes(i + 2, length - 2));
                        }
                        i += length - 1;
                }

                options.add(option);
            }
        }

        return options;
    }

    public Option getOption(Option wanted) {
        for (Option option : getOptions()) {
            if (option.id == wanted.id) {
                return option;
            }
        }

        return null;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof IpHeader) {
            IpHeader header = (IpHeader) previousHeaders.getLast();

            return header.getNextHeader() == IpHeader.Protocol.Tcp;
        }

        return false;
    }

    public long getNextSequenceNumber() {
        return getSequenceNumber() + getPayloadLength();
    }

    @Override
    public Signature getSession() {
        IpHeader ipHeader = (IpHeader) previousHeader;

        return new Session(ipHeader.getSourceAddress(), ipHeader.getDestinationAddress(),
                getSourcePort(), getDestinationPort());
    }

}
