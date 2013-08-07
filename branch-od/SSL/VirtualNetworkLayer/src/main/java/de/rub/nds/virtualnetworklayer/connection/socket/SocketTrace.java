package de.rub.nds.virtualnetworklayer.connection.socket;

import de.rub.nds.virtualnetworklayer.connection.Connection;
import de.rub.nds.virtualnetworklayer.packet.BytePacket;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class holds a trace of all packets in arrival order.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class SocketTrace extends Connection.Trace<BytePacket> {
    private List<BytePacket> packets = new ArrayList<BytePacket>();

    public BytePacket get(int position) {
        return packets.get(position);
    }

    public int size() {
        return packets.size();
    }

    BytePacket add(BytePacket packet) {
        packets.add(packet);

        return packet;
    }

    @Override
    protected List<BytePacket> getPackets() {
        return packets;
    }

    @Override
    public Iterator<BytePacket> iterator() {
        return packets.iterator();
    }
}
