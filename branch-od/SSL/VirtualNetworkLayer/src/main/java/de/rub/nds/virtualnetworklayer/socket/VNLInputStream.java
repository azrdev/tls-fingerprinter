package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
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
    private final PcapConnection connection;

    /**
     * Package private constructor. Only package classes (such as the customized
     * socket) are able to create instances.
     *
     * @param pcapConnection Connection object
     */
    VNLInputStream(final PcapConnection pcapConnection) {
        this.connection = pcapConnection;
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

        if (bytes == null) {
            throw new NullPointerException();
        }
        if (offset < 0 || len < 0) {
            throw new IllegalArgumentException(
                    "Only positive values are allowed");
        } else if (offset > len || bytes.length < len + offset) {
            throw new IndexOutOfBoundsException();
        }

        try {
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
        } catch (IOException e) {
            // something went wrong during read - Timeout? 
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
        Packet result = null;
        synchronized(connection) {
            result = connection.read(1000);
        }
                
        return result;
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
     * @param offset Offset in the passed array where to start storing read
     * packets
     * @param len Number of read packets.
     * @return Number of read raw packet from the connection.
     * @throws IOException
     */
    public int readPackets(final Packet[] packets, final int offset,
            final int len) throws IOException {
        int i = 0;

        if (packets == null) {
            throw new NullPointerException();
        }
        if (offset < 0 || len < 0) {
            throw new IllegalArgumentException(
                    "Only positive values are allowed");
        } else if (offset > len || packets.length < len + offset) {
            throw new IndexOutOfBoundsException();
        }

        try {
            while (i < len) {
                packets[offset + i] = readPacket();
                i++;
            }
        } catch (IOException e) {
            // something went wrong during read - Timeout? 
        }
        
        return i;
    }
}
