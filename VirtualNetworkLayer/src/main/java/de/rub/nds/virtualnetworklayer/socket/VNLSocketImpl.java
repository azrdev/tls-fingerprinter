package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.Connection.Trace;
import de.rub.nds.virtualnetworklayer.connection.socket.SocketConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;

/**
 * VNL socket implementation.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2012
 */
class VNLSocketImpl extends SocketImpl {
/**
     * Connection object.
     */
    private SocketConnection connection;

    /**
     * Package private constructor. Only package classes (such as the customized
     * socket) are able to create instances.
     */
    VNLSocketImpl() {
        
    }

    @Override
    protected void create(boolean stream) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void connect(String host, int port) throws IOException {
        connection = SocketConnection.create(host, port);
    }

    @Override
    protected void connect(InetAddress address, int port) throws IOException {
        connection = SocketConnection.create(address.getHostAddress(), port);
    }

    @Override
    protected void connect(SocketAddress address, int timeout) throws
            IOException {
        if (address instanceof InetSocketAddress) {
            InetSocketAddress inetAddr = (InetSocketAddress) address;
            connection = SocketConnection.create(inetAddr.getHostName(),
                    inetAddr.getPort());
        } else {
            throw new IOException("Only Sockets of type InetSocketAddress "
                    + "are supported.");
        }
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
        return new VNLInputStream(connection);
    }

    @Override
    protected OutputStream getOutputStream() throws IOException {
        return new VNLOutputStream(connection);
    }

    @Override
    protected int available() throws IOException {
        return connection.available();
    }

    @Override
    protected void close() throws IOException {
        connection.close();
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
    
    /**
     * Get the current trace of the connection.
     * @return Connection trace
     */
    public Trace getTrace() {
        return connection.getTrace();
    }
}
