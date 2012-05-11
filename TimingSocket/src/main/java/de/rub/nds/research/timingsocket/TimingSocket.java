package de.rub.nds.research.timingsocket;

import java.io.IOException;
import java.net.*;

/**
 * Timing socket for exact time measurement.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 11, 2012
 */
public class TimingSocket extends Socket {

    public TimingSocket() throws SocketException {
        super(new TimingSocketImpl());

    }

    public TimingSocket(final String host, final int port)
            throws SocketException, IOException {
        this();
        final SocketAddress socketAddress = new InetSocketAddress(host, port);
        connect(socketAddress);
    }

    public TimingSocket(final InetAddress address, final int port)
            throws IOException {
        this();
        final SocketAddress socketAddress = new InetSocketAddress(address, port);
        connect(socketAddress);
    }

    public TimingSocket(final String host, final int port,
            final InetAddress localAddr, final int localPort)
            throws IOException {
        this();
        final SocketAddress localSocketAddress = new InetSocketAddress(localAddr,
                localPort);
        bind(localSocketAddress);
        final SocketAddress socketAddress = new InetSocketAddress(host, port);
        connect(socketAddress);
    }

    public TimingSocket(final InetAddress address, final int port,
            final InetAddress localAddr, final int localPort)
            throws IOException {
        this();
        final SocketAddress localSocketAddress = new InetSocketAddress(localAddr,
                localPort);
        bind(localSocketAddress);
        final SocketAddress socketAddress = new InetSocketAddress(address, port);
        connect(socketAddress);
    }
}
