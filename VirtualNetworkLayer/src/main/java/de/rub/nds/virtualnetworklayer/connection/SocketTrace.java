package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.BytePacket;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;


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

    public long getTrafficCountBetween(long from, long to) {
        int position = Math.abs(Collections.binarySearch(packets, from) + 1);

        long trafficCount = 0;
        for (int i = position; i < size() && get(i).getTimeStamp() <= to; i++) {
            trafficCount += get(i).getContent().length;
        }

        return trafficCount;
    }

    @Override
    public Iterator<BytePacket> iterator() {
        return packets.iterator();
    }
}
