package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedList;

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

    public ReassembledPacket getCroppedPacket() {
        return ReassembledPacket.createCroppedPacket(this);
    }

    public ReassembledPacket getExtendedPacket() {
        return ReassembledPacket.createExtendedPacket(this);
    }

    public boolean isComplete() {
        return !payload.hasRemaining();
    }

    public LinkedList<PcapPacket> getPackets() {
        return packets;
    }

    public Header getFragmentedHeader() {
        return fragmentedHeader;
    }

    public LinkedList<Integer> getLengths() {
        return lengths;
    }

    public int getReassembledPayloadLength() {
        return fragmentedHeader.getLength() + fragmentedHeader.getPayloadLength();
    }
}
