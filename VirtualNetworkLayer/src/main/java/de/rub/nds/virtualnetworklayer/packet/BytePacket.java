package de.rub.nds.virtualnetworklayer.packet;


import de.rub.nds.virtualnetworklayer.util.Util;

public class BytePacket implements Comparable<Long>, Packet {

    private byte[] content;
    private Direction direction;
    private long timeStamp;

    public BytePacket(byte[] content, Direction direction) {
        this.content = content;
        this.direction = direction;
        this.timeStamp = Util.now();
    }

    @Override
    public long getTimeStamp() {
        return timeStamp;
    }

    @Override
    public byte[] getContent() {
        return content;
    }

    @Override
    public Direction getDirection() {
        return direction;
    }

    @Override
    public int compareTo(Long timeStamp) {
        if (timeStamp <= getTimeStamp()) {
            return 1;
        }

        return -1;
    }
}
