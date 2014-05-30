package de.rub.nds.virtualnetworklayer.packet.header;

import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.StringFormattable;
import de.rub.nds.virtualnetworklayer.util.formatter.StringFormatter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.LinkedList;

/**
 * A header can be registered with {@link de.rub.nds.virtualnetworklayer.packet.PacketHandler}:
 * <ul>
 * <li>add type to registy {@link de.rub.nds.virtualnetworklayer.packet.Headers}</li>
 * <li>implement {@link #getId()} (for uniqueness use id from registry {@code Headers.*.getId()})</li>
 * <li>implement {@link #getLength()}</li>
 * <li>implement {@link #isBound(java.util.LinkedList, de.rub.nds.virtualnetworklayer.pcap.Pcap.DataLinkType)}</li>
 * <li><i>optionally</i></i> implement {@link #getPayloadLength()}</li>
 * <li><i>optionally</i> implement {@link #isFragmented()}</li>
 * <li>implement header fields with {@code get<b>FieldName</b>} using the protected getters</li>
 * <li><i>optionally</i> annotate with {@link de.rub.nds.virtualnetworklayer.util.formatter.Format} for pretty printing</li>
 * <li>register with {@link de.rub.nds.virtualnetworklayer.packet.PacketHandler#registerHeader(Header)}</li>
 * </ul>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class Header implements Cloneable, StringFormattable {
    public static class Option<T> {
        private T type;
        private int length;
        private byte[] data;

        public Option(T type, int length, byte[] data) {
            this.type = type;
            this.length = length;
            this.data = data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }

        public int getUShort() {
            return getData().getShort() & 0xffff;
        }

        public int getUByte() {
            return getData().get() & 0xFF;
        }

        public ByteBuffer getData() {
            return ByteBuffer.wrap(data);
        }

        public T getType() {
            return type;
        }

        public int getLength() {
            return length;
        }

        @Override
        public String toString() {
            return type.toString();
        }
    }

    private ByteBuffer payload;

    protected final int getFirstNibble(int offset) {
        return (payload.get(offset) & 0xF0) >> 4;
    }

    protected final int getSecondNibble(int offset) {
        return (payload.get(offset) & 0x0F);
    }

    protected final int getByte(int offset) {
        return payload.get(offset);
    }

    protected final int getUByte(int offset) {
        return payload.get(offset) & 0xFF;
    }

    protected final short getShort(int offset) {
        return payload.getShort(offset);
    }

    protected final int getUShort(int offset) {
        return payload.getShort(offset) & 0xffff;
    }

    protected final long getUInteger(int offset) {
        return ((long) payload.getInt(offset) & 0xffffffffL);
    }

    protected final int getInteger(int offset) {
        return payload.getInt(offset);
    }

    protected final long getLong(int offset) {
        return payload.getLong(offset);
    }

    protected final byte[] getBytes(int offset, int length) {
        if (payload.hasArray()) {
            return Arrays.copyOfRange(this.payload.array(), getOffset() + offset, getOffset() + offset + length);
        }

        byte[] array = new byte[length];
        for (int i = 0; i < length; i++) {
            array[i] = payload.get(offset + i);
        }

        return array;
    }

    protected final int getBufferLength() {
        return this.payload.limit();
    }

    public final int getOffset() {
        if (payload.hasArray()) {
            return payload.arrayOffset();
        }

        return 0;
    }

    public final int getPayloadOffset() {
        return getOffset() + getLength();
    }

    /**
     * @return payload as raw byte array
     */
    public final byte[] getPayload() {
        return getBytes(getLength(), getPayloadLength());
    }

    public final byte[] getHeaderAndPayload() {
    	return getBytes(0, getLength() + getPayloadLength());
    }
    
    public Header clone() {
        try {
            return (Header) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public final void peer(ByteBuffer payload) {
        this.payload = decode(payload);
        payload.position(0);
    }

    public boolean isCorrupted() {
        if (this instanceof Checksum) {
            Checksum checksum = (Checksum) this;
            return !Arrays.equals(checksum.getCalcuatedChecksum(), checksum.getChecksum());
        }

        return false;
    }

    /**
     * Returns decoded byte buffer.
     * The default byte order is big endian.
     *
     * @param payload encoded byte buffer
     * @return decoded byte buffer
     * @see EncodedHeader for charset decoding
     */
    protected ByteBuffer decode(ByteBuffer payload) {
        return payload.order(ByteOrder.BIG_ENDIAN);
    }

    /**
     * Returns whether this header is fragmented.
     * It is usually sufficient to specifiy {@link #getPayloadLength()}.
     *
     * @return whether this header is fragmented
     */
    public boolean isFragmented() {
        return getPayloadLength() > payload.limit();
    }

    /**
     * Returns payload length (if known), otherwise the remaining bytes of this packet,
     * which might be limited by the previous header.
     * </p>
     * Returns {@link Integer#MAX_VALUE} if length is unknown and this header
     * might be fragmented (e.g Http Tcp stream {@link de.rub.nds.virtualnetworklayer.packet.header.application.HttpHeader}).
     *
     * @return payload length in bytes
     */
    public int getPayloadLength() {
        return this.payload.limit() - getLength();
    }

    /**
     * @return header length in bytes
     */
    public abstract int getLength();

    /**
     * @return unique id
     * @see de.rub.nds.virtualnetworklayer.packet.Headers
     */
    public abstract int getId();

    /**
     * @param previousHeaders chronological ordered list of previous headers
     * @param dataLinkType    {@link de.rub.nds.virtualnetworklayer.pcap.Pcap.DataLinkType}
     * @return whether a header of this type follows previousHeaders
     */
    public abstract boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType);

    @Override
    public String toString() {
        String canonicalName = this.getClass().getCanonicalName();

        if (canonicalName.length() > 45) {
            return canonicalName.substring(45);
        }

        return this.getClass().getSimpleName();
    }

    /**
     * @return pretty printed header
     * @see StringFormattable
     */
    public String toFormattedString() {
        return StringFormatter.toString(this);
    }
}
