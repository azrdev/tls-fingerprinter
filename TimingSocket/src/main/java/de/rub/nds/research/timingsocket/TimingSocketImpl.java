package de.rub.nds.research.timingsocket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;

/**
 * Implementation of a timing socket for exact time measurement.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 11, 2012
 */
public class TimingSocketImpl extends SocketImpl {

    @Override
    protected void create(boolean stream) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void connect(String host, int port) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void connect(InetAddress address, int port) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void connect(SocketAddress address, int timeout) throws
            IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void bind(InetAddress host, int port) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void listen(int backlog) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void accept(SocketImpl s) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected InputStream getInputStream() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected OutputStream getOutputStream() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected int available() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void close() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void sendUrgentData(int data) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setOption(int optID, Object value) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Object getOption(int optID) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
