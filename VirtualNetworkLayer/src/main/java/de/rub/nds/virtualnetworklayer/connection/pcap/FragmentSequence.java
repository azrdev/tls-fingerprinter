package de.rub.nds.virtualnetworklayer.connection.pcap;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.io.ByteArrayOutputStream;
import java.util.LinkedList;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class FragmentSequence {
    private LinkedList<PcapPacket> packets = new LinkedList<PcapPacket>();
    private LinkedList<Integer> lengths = new LinkedList<Integer>();
    private Header fragmentedHeader;
    private ByteArrayOutputStream payload;
    private int remaining;

    public FragmentSequence(PcapPacket packet) {
        fragmentedHeader = packet.getFragmentedHeader();

        if (fragmentedHeader == null || fragmentedHeader.getPayloadLength() == Integer.MAX_VALUE) {
            createBuffer(Integer.MAX_VALUE);
        } else {
            createBuffer(getReassembledPayloadLength());
        }

        if (fragmentedHeader != null) {
            add(packet, fragmentedHeader.getOffset());
        } else {
            add(packet, 0);
        }
    }

    private void createBuffer(int length) {
        if (length == Integer.MAX_VALUE) {
            payload = new ByteArrayOutputStream();
            remaining = Integer.MAX_VALUE;
        } else {
            payload = new ByteArrayOutputStream(length);
            remaining = length;
        }
    }

    public byte[] getReassembledPayload() {
        return payload.toByteArray();
    }

    void add(PcapPacket packet) {
        Header tcpHeader = packet.getHeader(TcpHeader.Id);
        add(packet, tcpHeader.getPayloadOffset());
    }

    private void add(PcapPacket packet, int offset) {
        int length = Math.min(packet.getLength() - offset, remaining);
        lengths.add(length);
        remaining -= length;

        payload.write(packet.getContent(), offset, length);
        packets.add(packet);
    }

    public ReassembledPacket getCroppedPacket() {
        return ReassembledPacket.createCroppedPacket(this);
    }

    public ReassembledPacket getExtendedPacket() {
        return ReassembledPacket.createExtendedPacket(this);
    }

    public boolean isComplete() {
        TcpHeader tcpHeader = packets.getLast().getHeader(TcpHeader.Id);
        return remaining == 0 || tcpHeader.getFlags().contains(TcpHeader.Flag.FIN);
    }

    public void merge(FragmentSequence sequence) {
		try {

			for (PcapPacket packet : sequence.getPackets()) {
				add(packet);

			}
		} catch (Exception e) {
			// TODO: Fix this, this might trow exceptions

		}
    }

    /**
     * Returns remaining bytes until sequence completion or
     * {@link Integer#MAX_VALUE} if unknown.
     *
     * @return remaining bytes until completion
     */
    public int getRemaining() {
        return remaining;
    }

    /**
     * @return a list of original packets fragment sequence was reassembled from
     */

    public LinkedList<PcapPacket> getPackets() {
        return packets;
    }

    /**
     * @return fragmented header, which triggered reassembly
     */
    public Header getFragmentedHeader() {
        return fragmentedHeader;
    }

    /**
     * Returns the fragments lengths, the reassembled payload's length accumulates over.
     * These are in same order as getPackets().
     * <p/>
     * {@code
     * accumulate(+ , getLengths(), 0) == getReassembledPayloadLength();
     * }
     *
     * @return a list of fragments lengths
     */
    public LinkedList<Integer> getLengths() {
        return lengths;
    }

    public int getReassembledPayloadLength() {
        if (fragmentedHeader == null) {
            return payload.size();
        }

        if (fragmentedHeader.getPayloadLength() == Integer.MAX_VALUE) {
            return fragmentedHeader.getLength() + payload.size();
        }

        return fragmentedHeader.getLength() + fragmentedHeader.getPayloadLength();
    }
}
