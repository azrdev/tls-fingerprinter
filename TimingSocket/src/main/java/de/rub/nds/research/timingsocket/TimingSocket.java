package de.rub.nds.research.timingsocket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;

/**
 * Timing socket for exact time measurement.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 11, 2012
 */
public class TimingSocket extends Socket {
    
    public TimingSocket() throws SocketException  {
        super(new TimingSocketImpl());
    }
    
    public TimingSocket(String host, int port) throws SocketException {
        this();
        // TODO
    }
    
    public TimingSocket(InetAddress address, int port) throws IOException {
        this();
        // TODO
    }
    
    public TimingSocket(String host, int port, InetAddress localAddr,
                  int localPort) throws IOException {
        this();
        // TODO
    }
    
    public TimingSocket(InetAddress address, int port, InetAddress localAddr,
                  int localPort) throws IOException {
        this();
        // TODO
    }
}
