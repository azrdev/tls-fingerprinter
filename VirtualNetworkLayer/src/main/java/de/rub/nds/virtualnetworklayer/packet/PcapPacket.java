package de.rub.nds.virtualnetworklayer.packet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.Session;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;
import de.rub.nds.virtualnetworklayer.util.formatter.StringFormattable;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

/**
 * Implements a packet reported by pcap.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class PcapPacket implements Packet, StringFormattable {
    private LinkedList<Header> headers;
    private long timeStamp;
    private ByteBuffer byteBuffer;
    private Direction direction;
    private int length;

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

    /**
     * Returns header (by id) if found, else null.
     *
     * @param id header id
     * @return header
     */
    public <T extends Header> T getHeader(int id) {
        for (Header header : headers) {
            if (header.getId() == id) {
                return (T) header;
            }
        }

        return null;
    }

    /**
     * Convenience method for typed lookup.
     *
     * @param header header type
     * @return header
     * @see #getHeader(int)
     */
    public <T extends Header> T getHeader(Headers header) {
        return getHeader(header.getId());
    }

	public <T extends Header> List<T> getHeaders(Headers header) {
		List<T> filteredHeaders = new LinkedList<T>();
		for(Header h : headers) {
			if(h.getId() == header.getId()) {
				filteredHeaders.add((T) h);
			}
		}
		return filteredHeaders;
	}

    /**
     * Returns <b>ordinal</b><sup>th</sup> header (by id) if found, else null.
     *
     * @param id      header id
     * @param ordinal ordinal number (zero based)
     * @return header
     */
    public <T extends Header> T getHeader(int id, int ordinal) {
        int position = 0;
        for (Header header : headers) {
            if (header.getId() == id) {

                if (position == ordinal) {
                    return (T) header;
                }

                position++;
            }
        }

        return null;
    }

    /**
     * Convenience method for typed lookup.
     *
     * @param header  header type
     * @param ordinal ordinal number (zero based)
     * @return header
     * @see #getHeader(int, int)
     */
    public <T extends Header> T getHeader(Headers header, int ordinal) {
        return getHeader(header.getId(), ordinal);
    }

    /**
     * Returns whether packet contains a header of this id.
     *
     * @param id
     * @return whether packet contains a header of this id
     */
    public boolean hasHeader(int id) {
        return getHeader(id) != null;
    }

    /**
     * Convenience method for typed lookup.
     *
     * @param header
     * @return whether packet contains a header of this type
     * @see #hasHeader(int)
     */
    public boolean hasHeader(Headers header) {
        return hasHeader(header.getId());
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

    public SocketSession getSession() {
        for (Header header : headers) {
            if (header instanceof Session) {
                return ((Session) header).getSession(this);
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return Long.toString(timeStamp) + " " + getDirection() + " " + getSession();
    }

    public String toFormattedString() {
        StringBuilder builder = new StringBuilder();

        builder.append(toString()).append('\n');
        for (Header header : headers) {
            builder.append(header.toFormattedString());
        }

        return builder.toString();
    }
}
