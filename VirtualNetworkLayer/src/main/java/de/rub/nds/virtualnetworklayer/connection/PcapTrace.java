package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.nio.ByteBuffer;
import java.util.*;

public class PcapTrace extends Connection.Trace<PcapPacket> {

    public class FragmentSequence {
        private LinkedList<PcapPacket> packets = new LinkedList<PcapPacket>();
        private LinkedList<Integer> lengths = new LinkedList<Integer>();
        private Header fragmentedHeader;
        private ByteBuffer payload;

        public FragmentSequence(PcapPacket packet) {
            fragmentedHeader = packet.getFragmentedHeader();
            payload = ByteBuffer.allocate(getReassembledPayloadLength());
            add(packet, fragmentedHeader.getOffset());
        }

        public byte[] getReassembledPayload() {
            return Arrays.copyOfRange(payload.array(), 0, getReassembledPayloadLength());
        }

        void add(PcapPacket packet) {
            Header tcpHeader = packet.getHeader(TcpHeader.Id);
            add(packet, tcpHeader.getPayloadOffset());
        }

        void add(PcapPacket packet, int offset) {
            int length = Math.min(packet.getLength() - offset, payload.remaining());
            lengths.add(length);

            payload.put(packet.getContent(), offset, length);
            packets.add(packet);
        }

        public PcapPacket getCroppedPacket() {
            PcapPacket firstPacket = packets.getFirst();
            Header tcpHeader = firstPacket.getHeader(TcpHeader.Id);

            if (fragmentedHeader.getOffset() != tcpHeader.getPayloadOffset()) {
                int length = fragmentedHeader.getOffset();
                ByteBuffer byteBuffer = ByteBuffer.allocate(length);
                byteBuffer.put(firstPacket.getContent(), 0, length);
                byteBuffer.flip();

                return new PcapPacket(byteBuffer, firstPacket.getTimeStamp(), PacketHandler.getPacketHeaders(byteBuffer));
            }

            return null;
        }

        public PcapPacket getExtendedPacket() {
            PcapPacket lastPacket = packets.getLast();
            Header tcpHeader = lastPacket.getHeader(TcpHeader.Id);

            int length = lengths.getLast() + tcpHeader.getPayloadOffset();
            int remaining = lastPacket.getLength() - length;

            ByteBuffer byteBuffer = ByteBuffer.allocate(tcpHeader.getPayloadOffset() + getReassembledPayloadLength() + remaining);
            byteBuffer.put(lastPacket.getContent(), 0, tcpHeader.getPayloadOffset());
            byteBuffer.put(getReassembledPayload());

            if (remaining > 0) {
                byteBuffer.put(lastPacket.getContent(), length, remaining);
            }

            byteBuffer.flip();

            return new PcapPacket(byteBuffer, lastPacket.getTimeStamp(), PacketHandler.getPacketHeaders(byteBuffer));
        }

        public boolean isComplete() {
            return !payload.hasRemaining();
        }

        public List<PcapPacket> getPackets() {
            return packets;
        }

        public int getReassembledPayloadLength() {
            return fragmentedHeader.getLength() + fragmentedHeader.getPayloadLength();
        }
    }

    private PriorityQueue<PcapPacket> sequenceOrder;
    private ArrayList<PcapPacket> arrivalOrder = new ArrayList<PcapPacket>();

    private HashMap<Long, FragmentSequence> fragmentSequences = new HashMap<Long, FragmentSequence>();
    private TcpHeader.SequenceComparator comparator;

    PcapPacket add(PcapPacket packet) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        if (sequenceOrder == null) {
            comparator = new TcpHeader.SequenceComparator(packet);
            sequenceOrder = new PriorityQueue<PcapPacket>(10, comparator);
        }

        packet.setDirection(comparator.getDirection(packet));

        FragmentSequence sequence;

        if (fragmentSequences.containsKey(tcpHeader.getSequenceNumber())
                && !(sequence = fragmentSequences.get(tcpHeader.getSequenceNumber())).isComplete()) {
            sequence.add(packet);

            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);
            fragmentSequences.remove(tcpHeader.getSequenceNumber());

        } else if (packet.isFragmented()) {
            sequence = new FragmentSequence(packet);
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);
        }

        if (!sequenceOrder.contains(packet)) {
            sequenceOrder.add(packet);
        }

        arrivalOrder.add(packet);

        return packet;
    }

    public List<FragmentSequence> getFragmentSequences() {
        return new LinkedList<FragmentSequence>(fragmentSequences.values());
    }

    @Override
    public Iterator<PcapPacket> iterator() {
        return getArrivalOrder();
    }

    public Iterator<PcapPacket> getSequenceOrder() {
        return sequenceOrder.iterator();
    }

    public Iterator<PcapPacket> getArrivalOrder() {
        return arrivalOrder.iterator();
    }

    @Override
    public PcapPacket get(int position) {
        return arrivalOrder.get(position);
    }

    public int getLast(Packet.Direction direction) {
        for (int i = arrivalOrder.size() - 1; i >= 0; i--) {
            if (get(i).getDirection() == direction) {
                return i;
            }
        }

        return 0;
    }

    public int getNext(int position, Packet.Direction direction) {
        for (int i = position + 1; i < arrivalOrder.size(); i++) {
            if (arrivalOrder.get(i).getDirection() == direction) {
                return i;
            }
        }

        return position;
    }

    @Override
    public int size() {
        return arrivalOrder.size();
    }

}
