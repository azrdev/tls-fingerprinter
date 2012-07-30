package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.socket.SocketConnection;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import java.io.IOException;
import java.io.InputStream;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * Customized implementation of InputStream to deliver BytePackets
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2012
 */
public class VNLInputStream extends InputStream {

    /**
     * Connection object.
     */
    private final SocketConnection connection;

    /**
     * Package private constructor. Only package classes (such as the customized
     * socket) are able to create instances.
     *
     * @param socketConnection Connection object
     */
    VNLInputStream(final SocketConnection socketConnection) {
        this.connection = socketConnection;
    }

    @Override
    public int read() throws IOException {
        throw new NotImplementedException();
    }

    @Override
    public int read(final byte[] bytes, final int offset, final int len) throws
            IOException {
        int pointer = offset;
        byte[] tmpBytes;
		/*
		 * Remember, len is only an upper limit for the number of bytes to read.
		 * Returning less bytes than len is fine, as long as at least one byte
		 * is returend.
		 */
        while (pointer < len) {
            tmpBytes = readPacket().getContent();
            if (tmpBytes.length + pointer < len) {
                System.arraycopy(tmpBytes, pointer, bytes, pointer,
                        tmpBytes.length);
                pointer += tmpBytes.length;
            } else {
                System.arraycopy(tmpBytes, pointer, bytes, pointer,
                        len - pointer);
                pointer += len - pointer;
            }

        }

        return pointer;
    }

    /**
     * Reads a raw packet.
     *
     * @return Raw packet from the connection.
     * @throws IOException
     */
    public Packet readPacket() throws IOException {
        return connection.read(1000);
    }

    /**
     * Reads raw packets.
     *
     * @param packets Packet array to store read packets.
     * @return Number of read raw packet from the connection.
     * @throws IOException
     */
    public int readPackets(final Packet[] packets) throws IOException {
        return readPackets(packets, 0, packets.length);
    }

    /**
     * Reads raw packets.
     *
     * @param packets Packet array to store read packets.
     * @param off Offset in the passed array where to start storing read packets
     * @param len Number of read packets.
     * @return Number of read raw packet from the connection.
     * @throws IOException
     */
    public int readPackets(final Packet[] packets, final int off,
            final int len) throws IOException {
        for (int i = 0; i < len; i++) {
            packets[off + i] = readPacket();
        }

        return len;
    }
}
