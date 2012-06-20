package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.util.*;

public class PcapTrace extends Connection.Trace<PcapPacket> {

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

        if (fragmentSequences.containsKey(tcpHeader.getSequenceNumber())) {
            sequence = fragmentSequences.get(tcpHeader.getSequenceNumber());

            if (!sequence.isComplete()) {
                sequence.add(packet);

                fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);
                fragmentSequences.remove(tcpHeader.getSequenceNumber());

                if (sequence.isComplete()) {
                    if (sequence.getCroppedPacket() != null) {
                        sequenceOrder.add(sequence.getCroppedPacket());
                    }

                    sequenceOrder.add(sequence.getExtendedPacket());
                }

            }

        } else if (packet.isFragmented()) {
            sequence = new FragmentSequence(packet);
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);
        } else if (!sequenceOrder.contains(packet)) {
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
        return getSequenceOrder();
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
