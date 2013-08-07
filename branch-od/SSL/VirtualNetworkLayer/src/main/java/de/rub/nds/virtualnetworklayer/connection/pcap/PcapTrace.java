package de.rub.nds.virtualnetworklayer.connection.pcap;

import de.rub.nds.virtualnetworklayer.connection.Connection;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.util.*;

/**
 * This class holds a trace of all packets in arrival order and
 * reassembled sequence order.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class PcapTrace extends Connection.Trace<PcapPacket> {
    private ArrayList<PcapPacket> arrivalOrder = new ArrayList<PcapPacket>();
    private ArrayList<PcapPacket> sequenceOrder = new ArrayList<PcapPacket>();

    private HashMap<Long, FragmentSequence> fragmentSequences = new HashMap<Long, FragmentSequence>();
    private ArrayList<PcapPacket> retransmitted = new ArrayList<PcapPacket>();

    PcapPacket add(PcapPacket packet) {
        arrivalOrder.add(packet);

        if (packet.hasHeader(TcpHeader.Id)) {
            reassembleTcp(packet);
        } else {
            sequenceOrder.add(packet);
        }

        return packet;
    }

    private boolean sequenceOrderisContinued(PcapPacket packet) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        int last = getLastPosition(packet.getDirection());
        if (last != 0) {
            PcapPacket lastPacket = get(last);
            TcpHeader lastTcpHeader = lastPacket.getHeader(TcpHeader.Id);

            if (!lastTcpHeader.getNextSequenceNumber().equals(tcpHeader.getSequenceNumber())) {
                return false;
            }
        }

        return true;
    }

    private void reassembleTcp(PcapPacket packet) {
        TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

        if (fragmentSequences.containsKey(tcpHeader.getSequenceNumber())) {
            FragmentSequence sequence = fragmentSequences.remove(tcpHeader.getSequenceNumber());
            if (!sequence.isComplete()) {

                sequence.add(packet);
                mergeNonContinuousSequences(sequence, tcpHeader, packet);
                fragmentSequences.put(tcpHeader.getNextSequenceNumber(), sequence);

                if (sequence.isComplete()) {
                    addReassembledPacket(sequence);
                }

            }
        } else if (packet.isFragmented()) {
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), new FragmentSequence(packet));
        } else if (!sequenceOrderisContinued(packet)) {
            FragmentSequence afterLostFragment = new FragmentSequence(packet);
            fragmentSequences.put(tcpHeader.getSequenceNumber(), afterLostFragment);
            fragmentSequences.put(tcpHeader.getNextSequenceNumber(), afterLostFragment);
        } else {
            sequenceOrder.add(packet);
        }
    }

    private void mergeNonContinuousSequences(FragmentSequence sequence, TcpHeader tcpHeader, PcapPacket packet) {
        if (fragmentSequences.containsKey(tcpHeader.getNextSequenceNumber())) {
            retransmitted.add(packet);

            sequence.merge(fragmentSequences.remove(tcpHeader.getNextSequenceNumber()));
            tcpHeader = sequence.getPackets().getLast().getHeader(TcpHeader.Id);
            fragmentSequences.remove(tcpHeader.getNextSequenceNumber());
        }
    }

    private void addReassembledPacket(FragmentSequence sequence) {
        if (sequence.getCroppedPacket() != null) {
            sequenceOrder.add(sequence.getCroppedPacket());
        }

        sequenceOrder.add(sequence.getExtendedPacket());
    }

    public List<FragmentSequence> getFragmentSequences() {
        return new LinkedList<FragmentSequence>(fragmentSequences.values());
    }

    /**
     * @return reassembled packets in sequence order
     */
    @Override
    public Iterator<PcapPacket> iterator() {
        return getSequenceOrder();
    }

    /**
     * @return reassembled packets in sequence order
     */
    public Iterator<PcapPacket> getSequenceOrder() {
        return getPackets().iterator();
    }

    /**
     * @return original packets in arrival order
     */
    public Iterator<PcapPacket> getArrivalOrder() {
        return arrivalOrder.iterator();
    }

    /**
     * @return list of reassembled packets in sequence order
     */
    @Override
    protected List<PcapPacket> getPackets() {
        return new ArrayList<PcapPacket>(sequenceOrder);
    }

    public boolean hasIncompleteSequences() {
        for (FragmentSequence sequence : fragmentSequences.values()) {
            if (!sequence.isComplete()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param position
     * @return reassembeld packet at specified position in sequence
     */
    @Override
    public PcapPacket get(int position) {
        return sequenceOrder.get(position);
    }

    int getLastPosition(Packet.Direction direction) {
        for (int i = sequenceOrder.size() - 1; i >= 0; i--) {
            if (get(i).getDirection() == direction) {
                return i;
            }
        }

        return 0;
    }

    public PcapPacket getLast(Packet.Direction direction) {
        int position = getLastPosition(direction);

        if (position < size()) {
            return get(getLastPosition(direction));
        }

        return null;
    }

    public PcapPacket getLast() {
        if (size() > 0) {
            return get(size() - 1);
        }

        return null;
    }

    int getNextPosition(int position, Packet.Direction direction) {
        for (int i = position + 1; i < sequenceOrder.size(); i++) {
            if (sequenceOrder.get(i).getDirection() == direction) {
                return i;
            }
        }

        return position;
    }

    /**
     * @return retransmitted packets
     */
    public ArrayList<PcapPacket> getRetransmitted() {
        return retransmitted;
    }

    @Override
    public int size() {
        return sequenceOrder.size();
    }

}
