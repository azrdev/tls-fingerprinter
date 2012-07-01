package de.rub.nds.virtualnetworklayer.packet;


import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * Implements a packet solely containing raw byte data.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class BytePacket implements Packet {
    private byte[] content;
    private Direction direction;
    private long timeStamp;

    public BytePacket(byte[] content, Direction direction) {
        this(content, direction, Util.now());
    }

    public BytePacket(byte[] content, Direction direction, long timeStamp) {
        this.content = content;
        this.direction = direction;
        this.timeStamp = timeStamp;
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
    public String toString() {
        return new Long(timeStamp).toString() + " " + getDirection();
    }
}
