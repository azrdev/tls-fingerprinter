package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.nio.ByteBuffer;

public class ReassembledPacket extends PcapPacket {

    public static enum Type {
        Cropped, Extended
    }

    private FragmentSequence fragmentSequence;
    private Type type;

    private ReassembledPacket(Type type, ByteBuffer byteBuffer, PcapPacket packet, FragmentSequence fragmentSequence) {
        super(byteBuffer, packet.getTimeStamp(), PacketHandler.getPacketHeaders(byteBuffer));

        this.fragmentSequence = fragmentSequence;
        this.type = type;
        setDirection(packet.getDirection());
    }

    public static ReassembledPacket createExtendedPacket(FragmentSequence sequence) {
        PcapPacket lastPacket = sequence.getPackets().getLast();
        Header tcpHeader = lastPacket.getHeader(TcpHeader.Id);

        int length = sequence.getLengths().getLast() + tcpHeader.getPayloadOffset();
        int remaining = lastPacket.getLength() - length;

        ByteBuffer byteBuffer = ByteBuffer.allocate(tcpHeader.getPayloadOffset() + sequence.getReassembledPayloadLength() + remaining);
        byteBuffer.put(lastPacket.getContent(), 0, tcpHeader.getPayloadOffset());
        byteBuffer.put(sequence.getReassembledPayload());

        if (remaining > 0) {
            byteBuffer.put(lastPacket.getContent(), length, remaining);
        }

        byteBuffer.flip();

        return new ReassembledPacket(ReassembledPacket.Type.Extended, byteBuffer, lastPacket, sequence);
    }

    public static ReassembledPacket createCroppedPacket(FragmentSequence sequence) {
        PcapPacket firstPacket = sequence.getPackets().getFirst();
        Header tcpHeader = firstPacket.getHeader(TcpHeader.Id);

        Header fragmentedHeader = sequence.getFragmentedHeader();
        if (fragmentedHeader.getOffset() != tcpHeader.getPayloadOffset()) {
            int length = fragmentedHeader.getOffset();
            ByteBuffer byteBuffer = ByteBuffer.allocate(length);
            byteBuffer.put(firstPacket.getContent(), 0, length);
            byteBuffer.flip();

            return new ReassembledPacket(ReassembledPacket.Type.Cropped, byteBuffer, firstPacket, sequence);
        }

        return null;
    }

    public FragmentSequence getFragmentSequence() {
        return fragmentSequence;
    }

    @Override
    public String toString() {
        return type + " " + super.toString();
    }
}
