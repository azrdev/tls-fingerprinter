package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.nio.ByteBuffer;
import java.util.*;

public class PcapTrace extends Connection.Trace<PcapPacket> {

    public class FragmentSequence {
        private List<PcapPacket> packets = new LinkedList<PcapPacket>();
        private int offset;
        private ByteBuffer byteBuffer;


        public FragmentSequence(PcapPacket packet) {
            offset = packet.getFragmentedHeader().getOffset();
            packets.add(packet);
        }

        public PcapPacket reassemble() {
            byteBuffer = ByteBuffer.allocate(getLength());
            byte[] firstPayload = Arrays.copyOfRange(packets.get(0).getContent(), offset, packets.get(0).getLength());
            byteBuffer.put(packets.get(1).getContent());
            byteBuffer.put(firstPayload);

            return new PcapPacket(byteBuffer, 0, PacketHandler.getPacketHeaders(byteBuffer, 5));
        }

        public int getOffset() {
            return offset;
        }

        public int getLength() {
            int length = 0;
            Iterator<PcapPacket> iterator = packets.iterator();
            length += iterator.next().getLength() - offset;
            length += iterator.next().getLength();

            return length;
        }
    }

    private PriorityQueue<PcapPacket> sequenceOrder;
    private ArrayList<PcapPacket> arrivalOrder;

    private HashMap<Long, FragmentSequence> fragmentSequences = new HashMap<Long, FragmentSequence>();
    private TcpHeader.SequenceComparator comparator;

    //TODO modifier
    public PcapPacket add(PcapPacket packet) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        if (sequenceOrder == null) {
            comparator = new TcpHeader.SequenceComparator(packet);
            sequenceOrder = new PriorityQueue<PcapPacket>(10, comparator);
            arrivalOrder = new ArrayList<PcapPacket>();
        }

        packet.setDirection(comparator.getDirection(packet));

        FragmentSequence sequence;

        if (fragmentSequences.containsKey(tcpHeader.getSequenceNumber())) {
            sequence = fragmentSequences.get(tcpHeader.getSequenceNumber());
            sequence.packets.add(packet);
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);

        } else if (packet.isFragmented()) {
            sequence = new FragmentSequence(packet);
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);
        }


        sequenceOrder.add(packet);
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

    @Override
    public int size() {
        return arrivalOrder.size();
    }


}
