package de.rub.nds.virtualnetworklayer.packet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.util.Signature;

import java.nio.ByteBuffer;
import java.util.List;

public class PcapPacket implements Packet {

    private List<Header> headers;
    private long timeStamp;
    private ByteBuffer byteBuffer;
    private int fragmentedHeader;
    private Direction direction;

    public PcapPacket(ByteBuffer byteBuffer, long timeStamp, List<Header> headers) {
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
        fragmentedHeader = 0;

        for (Header header : headers) {
            if (header.isFragmented()) {
                return true;
            }

            fragmentedHeader++;
        }

        return false;
    }

    public int getLength() {
        return byteBuffer.limit();
    }

    public Header getFragmentedHeader() {
        if (fragmentedHeader == 0) {
            isFragmented();
        }

        return headers.get(fragmentedHeader);
    }

    public boolean isContinuedBy(PcapPacket packet) {
        for (int i = fragmentedHeader; i >= 0; i--) {
            if (headers.get(i).isContinuedBy(packet)) {
                return true;
            }
        }

        return false;
    }

    public Signature getSession() {
        for (Header header : headers) {
            if (header.getSession() != null) {
                return header.getSession();
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return new Long(timeStamp).toString();
    }
}
