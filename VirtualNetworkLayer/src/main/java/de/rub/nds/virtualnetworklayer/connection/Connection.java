package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.BytePacket;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * This is the interface all connections should implement.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface Connection extends Closeable {
    public static final int DefaultTimeout = 1000;

    public static abstract class Trace<T extends Packet> implements Iterable<T> {

        public static class TimeStampComparator implements Comparator<Packet> {
            @Override
            public int compare(Packet packet, Packet packet1) {
                if (packet1.getTimeStamp() <= packet.getTimeStamp()) {
                    return 1;
                }

                return -1;
            }
        }

        /**
         * Returns the traffic volume in bytes between from and to.
         * {@link de.rub.nds.virtualnetworklayer.util.Util#now()}
         *
         * @param from timestamp in mili seconds
         * @param to   timestamp in mili seconds
         * @return traffic volume in bytes
         */
        public long getTrafficVolumeBetween(long from, long to) {
            int position = Math.abs(Collections.binarySearch(getPackets(), new BytePacket(null, null, from), new TimeStampComparator()) + 1);

            long trafficCount = 0;
            for (int i = position; i < size() && get(i).getTimeStamp() <= to; i++) {
                trafficCount += get(i).getContent().length;
            }

            return trafficCount;
        }

        protected abstract List<T> getPackets();

        public abstract T get(int position);

        public abstract int size();

    }

    /**
     * Returns number greater zero, if packet can be read without blocking.
     * For concrete implementation see subclass.
     *
     * @return number greater zero, if packet can be read without blocking.
     * @throws IOException
     */
    public int available() throws IOException;

    /**
     * Reads the next available packet considering the specified timeout.
     *
     * @param timeout
     * @return next available packet
     * @throws IOException
     */
    public Packet read(int timeout) throws IOException;

    /**
     * Writes data.length bytes from the specified byte array to this connection.
     *
     * @param data
     * @return packet used for transport
     * @throws IOException
     */
    public Packet write(byte[] data) throws IOException;

    /**
     * @return trace
     * @see Trace
     */
    public Trace getTrace();

    /**
     * Closes this connection.
     */
    public void close();
}
