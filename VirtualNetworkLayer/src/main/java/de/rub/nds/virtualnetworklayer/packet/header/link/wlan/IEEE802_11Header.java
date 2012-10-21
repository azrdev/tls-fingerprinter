package de.rub.nds.virtualnetworklayer.packet.header.link.wlan;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Checksum;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.zip.CRC32;

/**
 * IEEE 802.11 (WLan)
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.DataLink)
public class IEEE802_11Header extends Header implements Checksum {
    private final static int Id = Headers.IEEE802_11.getId();

    public static class SequenceControl {
        private int sequenceControl;

        public SequenceControl(int sequenceControl) {
            this.sequenceControl = sequenceControl;
        }

        public int getFragmentNumber() {
            return sequenceControl & 0x0f;
        }

        public int getSequenceNumber() {
            return sequenceControl >> 4;
        }
    }

    public static enum Address {
        Destination,
        Source,
        BasicServiceSet,
        Recipient,
        Transmitter
    }

    public static enum Flag {
        ToDistributionSystem(0x01),
        FromDistributionSystem(0x02),
        MoreFragments(0x04),
        Retry(0x08),
        PowerManagement(0x10),
        MoreData(0x20),
        WEP(0x40),
        Order(0x80);

        private int position;

        private Flag(int position) {
            this.position = position;
        }
    }

    public static enum Type {
        Management,
        Control,
        Data;

        public SubType valueOf(int id) {
            SubType[] subTypes = null;

            if (this == Management) {
                subTypes = SubType.Management.values();
            } else if (this == Control) {
                subTypes = SubType.Control.values();
            } else if (this == Data) {
                subTypes = SubType.Data.values();
            }

            if (id < subTypes.length) {
                return subTypes[id];
            } else {
                return new SubType.Unknown(id);
            }
        }

    }

    public static interface SubType {
        public static enum Management implements SubType {
            AssociationRequest,
            AssociationResponse,
            ReassociationRequest,
            ReassociationResponse,
            ProbeRequest,
            ProbeResponse,
            Reserved,
            Reserved2,
            Beacon,
            ATIM,
            Disassociate,
            Authentication,
            Deauthentication,
            Action;

            @Override
            public int getAddressCount(Set<Flag> flags) {
                return 3;
            }

            @Override
            public int getAddressPosition(Address address, Set<Flag> flags) {
                switch (address) {
                    case Destination:
                        return 0;
                    case Source:
                        return 1;
                    case BasicServiceSet:
                        return 2;
                    default:
                        return -1;
                }
            }
        }

        public static enum Control implements SubType {
            Reserved(0),
            Reserved2(0),
            PowerSave(2),
            RequestToSend(2),
            ClearToSend(1),
            Acknowledgment(1),
            CFEnd(2),
            CFEndAndAck(2);

            private int addressCount;

            private Control(int addressCount) {
                this.addressCount = addressCount;
            }

            @Override
            public int getAddressCount(Set<Flag> flags) {
                return addressCount;
            }

            @Override
            public int getAddressPosition(Address address, Set<Flag> flags) {
                return -1;
            }

        }

        public static enum Data implements SubType {
            Data,
            DataAndCFAck,
            DataAndCFPoll,
            DataAndCFAckAndCFPoll,
            Null,
            CFAck,
            CFPoll,
            CFAckAndPoll,;

            @Override
            public int getAddressCount(Set<Flag> flags) {
                if (flags.contains(Flag.ToDistributionSystem) && flags.contains(Flag.FromDistributionSystem)) {
                    return 4;
                }

                return 3;
            }

            @Override
            public int getAddressPosition(Address address, Set<Flag> flags) {
                switch (address) {
                    case Destination:
                        if (!flags.contains(Flag.ToDistributionSystem)) {
                            return 0;
                        } else {
                            return 2;
                        }
                    case Source:
                        if (flags.contains(Flag.FromDistributionSystem) && flags.contains(Flag.ToDistributionSystem)) {
                            return 3;
                        } else if (flags.contains(Flag.FromDistributionSystem)) {
                            return 2;
                        } else {
                            return 1;
                        }
                    case BasicServiceSet:
                        if (flags.contains(Flag.FromDistributionSystem) && flags.contains(Flag.ToDistributionSystem)) {
                            return -1;
                        } else if (flags.contains(Flag.ToDistributionSystem)) {
                            return 0;
                        } else if (flags.contains(Flag.FromDistributionSystem)) {
                            return 1;
                        } else {
                            return 2;
                        }
                    default:
                        return -1;
                }
            }
        }

        public static class Unknown implements SubType {
            private int id;

            public Unknown(int id) {
                this.id = id;
            }

            @Override
            public String toString() {
                return String.valueOf(id);
            }

            @Override
            public int getAddressCount(Set<Flag> flags) {
                return 0;
            }

            @Override
            public int getAddressPosition(Address address, Set<Flag> flags) {
                return -1;
            }


        }

        int getAddressCount(Set<Flag> flags);

        int getAddressPosition(Address address, Set<Flag> flags);
    }


    private List<byte[]> addresses;
    private Set<Flag> flags;

    public int getProtocolVersion() {
        return getSecondNibble(0) & 0x03;
    }

    public Type getType() {
        int type = (getSecondNibble(0) & 0x0c) >> 2;
        if (type >= Type.values().length) {
            return null;
        }

        return Type.values()[type];
    }

    public SubType getSubType() {
        int subType = getFirstNibble(0);

        return getType().valueOf(subType);
    }

    public Set<Flag> getFlags() {
        if (flags == null) {
            flags = EnumSet.noneOf(Flag.class);
            int mask = getByte(1);

            for (Flag flag : Flag.values()) {
                if ((mask & flag.position) == flag.position) {
                    flags.add(flag);
                }
            }
        }

        return flags;
    }


    public int getDuration() {
        return getUShort(2);
    }

    public int getAddressCount() {
        return getSubType().getAddressCount(getFlags());
    }

    @Format(with = MacFormatter.class)
    public List<byte[]> getAddresses() {
        if (addresses == null) {
            addresses = new ArrayList<byte[]>();

            int start = 4;
            int count = getAddressCount();
            for (int i = 0; i < count && start + 6 < getBufferLength(); i++) {
                addresses.add(getBytes(start, 6));

                start += 6;
            }

            if (count == 4) {
                addresses.add(getBytes(start + 2, 6));
            }

        }

        return addresses;
    }

    public byte[] getAddress(Address address) {
        int position = getSubType().getAddressPosition(address, getFlags());
        if (position != -1 && position < getAddresses().size()) {
            return getAddresses().get(position);
        }

        return null;
    }

    public String getSsid() {
        if (getType() == Type.Management) {
            int offset = getLength();
            SubType subType = getSubType();

            if (subType == SubType.Management.Beacon || subType == SubType.Management.ProbeResponse) {
                offset += 12;
            } else if (subType == SubType.Management.ReassociationRequest) {
                offset += 10;
            } else if (subType == SubType.Management.AssociationRequest) {
                offset += 4;
            } else if (subType != SubType.Management.ProbeRequest) {
                return "";
            }

            if (getUByte(offset) == 0) {
                int length = getUByte(offset + 1);
                return new String(getBytes(offset + 2, length));
            }
        }

        return "";
    }

    @Override
    @Format(with = HexFormatter.class)
    public byte[] getChecksum() {
        return getBytes(getBufferLength() - 4, 4);
    }

    @Override
    @Format(with = HexFormatter.class)
    public byte[] getCalcuatedChecksum() {
        CRC32 crc = new CRC32();
        crc.update(getBytes(0, getPayloadLength()));

        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(crc.getValue());
        return new byte[]{buffer.get(7), buffer.get(6), buffer.get(5), buffer.get(4)};
    }

    @Format(with = StringFormatter.class)
    public SequenceControl getSequenceControl() {
        if (getType() == Type.Management || getType() == Type.Data) {
            return new SequenceControl(getUShort(22));
        }

        return null;
    }

    @Override
    public int getLength() {
        int length = 4 + getAddressCount() * 6;

        if (getType() == Type.Management || getType() == Type.Data) {
            length += 2;
        }

        //802.11e QoS
        if (getType() == Type.Data && getFirstNibble(0) >= 8) {
            length += 2;
        }

        return length;
    }

    @Override
    public int getPayloadLength() {
        return getBufferLength() - 4;
    }


    @Override
    public int getId() {
        return Id;
    }

    @Override
    public Header clone() {
        IEEE802_11Header header = (IEEE802_11Header) super.clone();
        header.addresses = null;
        header.flags = null;

        return header;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof RadiotapHeader)) {
            return getBufferLength() > 10 && getType() != null;
        }

        return dataLinkType == Pcap.DataLinkType.IEEE802_11;
    }
}
