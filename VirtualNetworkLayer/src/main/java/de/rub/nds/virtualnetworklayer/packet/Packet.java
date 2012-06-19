package de.rub.nds.virtualnetworklayer.packet;

public interface Packet {
    public static enum Direction {
        Response, Request
    }

    public abstract long getTimeStamp();

    public abstract byte[] getContent();

    public abstract Direction getDirection();

}
