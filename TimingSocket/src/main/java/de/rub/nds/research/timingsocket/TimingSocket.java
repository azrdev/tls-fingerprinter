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
        final SocketAddress socketAddr = new InetSocketAddress(host, port);
        connect(socketAddr);
    }

    public TimingSocket(final InetAddress address, final int port)
            throws IOException {
        this();
        final SocketAddress socketAddr = new InetSocketAddress(address, port);
        connect(socketAddr);
    }

    public TimingSocket(final String host, final int port,
            final InetAddress localAddr, final int localPort)
            throws IOException {
        this();
        final SocketAddress loclaSocketAddr = new InetSocketAddress(localAddr,
                localPort);
        bind(loclaSocketAddr);
        final SocketAddress socketAddr = new InetSocketAddress(host, port);
        connect(socketAddr);
    }

    public TimingSocket(final InetAddress address, final int port,
            final InetAddress localAddr, final int localPort)
            throws IOException {
        this();
        final SocketAddress localSocketAddr = new InetSocketAddress(localAddr,
                localPort);
        bind(localSocketAddr);
        final SocketAddress socketAddr = new InetSocketAddress(address, port);
        connect(socketAddr);
    }
}
