package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.socket.SocketConnection;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Customized implementation of OutputStream to deal with BytePackets
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2012
 */
public class VNLOutputStream extends OutputStream {

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
    VNLOutputStream(final SocketConnection socketConnection) {
        this.connection = socketConnection;
    }
    
    @Override
    public void write(final int b) throws IOException {
        connection.write(intToBytes(b));
    }
    
    /**
     * Converts an Integer to its byte[] representation.
     * @param toConvert Integer to convert
     * @return Byte representation of the passed integer
     */
    private byte[] intToBytes(final int toConvert) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(toConvert);
        
        return bb.array();
    }
}
