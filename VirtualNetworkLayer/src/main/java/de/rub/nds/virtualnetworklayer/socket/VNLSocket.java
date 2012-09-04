package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;

/**
 * Socket based on the underlying Virtual Network Layer.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2012
 */
public class VNLSocket extends Socket {

    /**
     * Instance of the implementing class.
     */
    private VNLSocketImpl vnlSocketImpl;

    /**
     * Create a VNL Socket.
     *
     * @throws SocketException
     */
    public VNLSocket() throws SocketException {
        this(new VNLSocketImpl());
    }

    /**
     * Dirrrty trick to be able to hold a copy of the VNLSocketImpl instance.
     *
     * @param socketImpl Instance of the VNLSocketImpl class
     * @throws SocketException
     */
    private VNLSocket(VNLSocketImpl socketImpl) throws SocketException {
        super(socketImpl);
        vnlSocketImpl = socketImpl;
    }

    @Override
    public VNLInputStream getInputStream() throws IOException {
        return (VNLInputStream) super.getInputStream();
    }

    @Override
    public VNLOutputStream getOutputStream() throws IOException {
        return (VNLOutputStream) super.getOutputStream();
    }

    /**
     * Get the underlying connection.
     *
     * @return Connection used by this socket
     */
    public PcapConnection getConnection() {
        return vnlSocketImpl.getConnection();
    }
}
