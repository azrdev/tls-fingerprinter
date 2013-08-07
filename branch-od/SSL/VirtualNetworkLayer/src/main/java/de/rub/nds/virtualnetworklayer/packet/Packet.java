package de.rub.nds.virtualnetworklayer.packet;

/**
 * This is the interface all packets should implement.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface Packet {
    public static enum Direction {
        Response, Request;

        public Direction flip() {
            return Direction.values()[(ordinal() + 1) % 2];
        }
    }

    /**
     * @return timestamp in nanoseconds
     */
    public abstract long getTimeStamp();

    /**
     * @return packet as raw byte array
     */
    public abstract byte[] getContent();

    /**
     * @return direction of packet
     * @see de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession#getDirection(PcapPacket)
     */
    public abstract Direction getDirection();

}
