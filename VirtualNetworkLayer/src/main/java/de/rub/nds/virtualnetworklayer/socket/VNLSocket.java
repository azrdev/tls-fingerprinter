package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.Connection.Trace;
import java.io.IOException;
import java.io.InputStream;
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

    /**
     * Get the current trace of the connection.
     * @return Connection trace
     */
    public Trace getTrace() {
        // this is not safe! Directly reveals the state of VNLSocketImpl
        
        // TODO deep copy or clone
        return vnlSocketImpl.getTrace();
    }
    
    @Override
    public VNLInputStream getInputStream() throws IOException {        
        return (VNLInputStream) super.getInputStream();
    }
    
    @Override
    public VNLOutputStream getOutputStream() throws IOException {        
        return (VNLOutputStream) super.getOutputStream();
    }
}
