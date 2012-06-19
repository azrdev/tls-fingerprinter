package de.rub.nds.virtualnetworklayer.packet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.Session;
import de.rub.nds.virtualnetworklayer.util.Signature;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public class PcapPacket implements Packet {
    private LinkedList<Header> headers;
    private long timeStamp;
    private ByteBuffer byteBuffer;
    private Direction direction;

    public PcapPacket(ByteBuffer byteBuffer, long timeStamp, LinkedList<Header> headers) {
        this.byteBuffer = byteBuffer;
        this.timeStamp = timeStamp;
        this.headers = headers;
    }

    @Override
    public long getTimeStamp() {
        return timeStamp;
    }

    public List<Header> getHeaders() {
        return headers;
    }

    public <T extends Header> T getHeader(int id) {
        for (Header header : headers) {
            if (header.getId() == id) {
                return (T) header;
            }
        }

        return null;
    }

    public <T extends Header> T getHeader(int id, int number) {
        int position = 0;
        for (Header header : headers) {
            if (header.getId() == id) {

                if (position == number) {
                    return (T) header;
                }

                position++;
            }
        }

        return null;
    }

    public boolean hasHeader(int id) {
        Header header = getHeader(id);

        return header != null;
    }

    @Override
    public byte[] getContent() {
        return byteBuffer.array();
    }

    @Override
    public Direction getDirection() {
        return direction;
    }

    public void setDirection(Direction direction) {
        this.direction = direction;
    }

    public boolean isFragmented() {
        return headers.getLast().isFragmented();
    }

    public int getLength() {
        return byteBuffer.limit();
    }

    public Header getFragmentedHeader() {
        if (!isFragmented()) {
            return null;
        }

        return headers.getLast();
    }

    public Signature getSession() {
        for (Header header : headers) {
            if (header instanceof Session) {
                return ((Session) header).getSession();
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return new Long(timeStamp).toString() + " " + getSession();
    }
}
