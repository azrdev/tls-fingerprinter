package de.rub.nds.virtualnetworklayer.socket;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import javax.imageio.IIOException;

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
    private PcapConnection connection;
    /**
     * Pcap instance - necessary for capturing.
     */
    private Pcap pcap;

    /**
     * Package private constructor. Only package classes (such as the customized
     * socket) are able to create instances.
     */
    VNLSocketImpl() {
    }

    @Override
    protected void create(final boolean stream) throws IOException {
        // since PcapConnection can't create without connect silently skip this
    }

    @Override
    protected void connect(final String host, final int port)
            throws IOException {
        this.address = InetAddress.getByName(host);
        this.port = port;
        connection = PcapConnection.create(this.address.getHostAddress(),
                this.port);
    }

    @Override
    protected void connect(final InetAddress address, final int port) throws
            IOException {
        this.address = address;
        this.port = port;
        connection = PcapConnection.create(this.address.getHostAddress(),
                this.port);
    }

    @Override
    protected void connect(final SocketAddress address, final int timeout)
            throws IOException {
        if (address instanceof InetSocketAddress) {
            InetSocketAddress inetAddr = (InetSocketAddress) address;
            this.address = InetAddress.getByName(inetAddr.getHostName());
            this.port = inetAddr.getPort();
            connection = PcapConnection.create(this.address.getHostAddress(),
                    this.port);
        } else {
            throw new IOException("Only Sockets of type InetSocketAddress "
                    + "are supported.");
        }
    }

    @Override
    protected void bind(final InetAddress host, final int port) throws
            IOException {
        this.address = host;
        this.port = port;
    }

    @Override
    protected void listen(final int backlog) throws IOException {
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);
        // open pcap on local live device
        pcap = Pcap.openLive();

    }

    @Override
    protected void accept(final SocketImpl s) throws IOException {
        if (pcap == null) {
            throw new IIOException("No Pcap instance available. You're trying "
                    + "to drop your ear on the wire, without having a wire! "
                    + "Call listen() first.");
        }

        // connection handler
        pcap.loopAsynchronous(new ConnectionHandler() {
            @Override
            public void newConnection(ConnectionHandler.Event event,
                    PcapConnection passedConnection) {
                if (event == ConnectionHandler.Event.New
                        && passedConnection.getSession().getDestinationPort()
                        == port) {
                    connection = passedConnection;
                }
            }
        });
    }

    @Override
    protected InputStream getInputStream() throws IOException {
        if(connection == null) {
            throw new IOException("No connection available ( == null).");
        }
        return new VNLInputStream(connection);
    }

    @Override
    protected OutputStream getOutputStream() throws IOException {
        if(connection == null) {
            throw new IOException("No connection available ( == null).");
        }
        return new VNLOutputStream(connection);
    }

    @Override
    protected int available() throws IOException {
        int result = -1;
        if(connection != null) {
            result = connection.available();
        }
        
        return result;
    }

    @Override
    protected void close() throws IOException {
        if(connection != null) {
            connection.close();
        }
    }

    @Override
    protected void sendUrgentData(final int data) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setOption(final int optID, final Object value) throws
            SocketException {
        // PcapConnection doesn't allow options to be set
    }

    @Override
    public Object getOption(final int optID) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Get the underlying connection.
     *
     * @return Connection used by this socket
     */
    public PcapConnection getConnection() {
        return this.connection;
    }
}
