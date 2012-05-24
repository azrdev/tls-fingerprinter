package de.rub.nds.research.timingsocket;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;


/**
 * Implementation of a timing socket for exact time measurement.
 *
 * @author Sebastian Schinzel - ssc@seecurity.org
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 23, 2012
 */
public class TimingSocketImpl extends SocketImpl {
    
    private class TimingOutputStream extends OutputStream {

        @Override
        public void close() throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        /**
         * We flush with every write, so we don't need this 
         * method (I guess...).
         */
        public void flush() throws IOException {
        }

        @Override
        public void write(byte[] bytes, int i, int i1) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    
        TimingSocketImpl tsi;

        /**
        * TimingOutputStream only works with an instance
        * of TimingSocketImpl.
        */
        private TimingOutputStream() {
        }

        public TimingOutputStream(TimingSocketImpl tsi) {
            this.tsi = tsi;
        }

        @Override
        public void write(int i) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void write(byte[] ar) throws IOException {
            tsi.write(ar);
        }
    }
    
    private class TimingInputStream extends InputStream {

        @Override
        public int available() throws IOException {
            return tsi.available();
        }

        @Override
        public void close() throws IOException {
            
            throw new UnsupportedOperationException("Not supported yet.");
            // super.close();
        }

        @Override
        public synchronized void mark(int i) {
            throw new UnsupportedOperationException("Not supported yet.");
            // super.mark(i);
        }

        @Override
        public boolean markSupported() {
            throw new UnsupportedOperationException("Not supported yet.");
            // return super.markSupported();
        }

        @Override
        public synchronized void reset() throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
            // super.reset();
        }

        @Override
        public long skip(long l) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
            // return super.skip(l);
        }
    
        TimingSocketImpl tsi;

        private TimingInputStream() {
        }

        public TimingInputStream(TimingSocketImpl tsi) {
            this.tsi = tsi;
        }

        @Override
        public int read(byte[] ar) throws IOException {
            return tsi.read(ar);
        }

        @Override
        public int read() throws IOException {
            return tsi.read();
        }

        @Override
        public int read(byte[] ar, int start, int end) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

    }
    
    static {
        String file = new File("").getAbsolutePath() + "/../TimingSocket/src/main/java/libnativecode.dylib";
        System.load(file);
    }
    private int file_desc;
    private OutputStream os;
    private InputStream is;

    @Override
    public void create(boolean stream) throws IOException {
        if(stream == false) {
            throw new UnsupportedOperationException("Datagram socket not supported yet. Use stream==true.");
        }
        
        file_desc = c_create(stream);
        
        if(file_desc < 0) {
            throw new IOException("Cannot create socket.");
        }
        
        os = new TimingOutputStream(this);
        is = new TimingInputStream(this);
    }
    public native int c_create(boolean stream);

    @Override
    public void connect(String host, int port) throws IOException {
        int ret = c_connect(file_desc, host, port);
        
        if(ret != 0) {
            throw new IOException("Cannot connect socket.");
        }
    }
    public native int c_connect(int socket, String host, int port);

    @Override
    protected void connect(InetAddress address, int port) throws IOException {
        String host = address.getCanonicalHostName();
        connect(host, port);
    }

    @Override
    protected void connect(SocketAddress address, int timeout) throws
            IOException {
        InetSocketAddress isa = (InetSocketAddress) address;
        connect(isa.getHostName(), isa.getPort());
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
        return is;
    }

    @Override
    protected OutputStream getOutputStream() throws IOException {
        return os;
    }

    @Override
    protected int available() throws IOException {
        int avail = c_available();
        if(avail > 0) {
            return 1400;
        } else {
            return 0;
        }
    }
    public native int c_available();

    @Override
    protected void close() throws IOException {
        c_close();
    }
    public native int c_close();

    @Override
    protected void sendUrgentData(int data) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setOption(int optID, Object value) throws SocketException {
        int ret = -1;
        if(optID == SocketOptions.SO_LINGER) {
            int value_int = (Integer) value;
            ret = c_setOption(optID, value_int);
        } else {
            //Todo: throw new UnsupportedOperationException("Option ID " + optID + " not supported yet.");
        }
        
        if(ret != 0) {
            //Todo: throw new SocketException("Could not set option");
        }
    }
    public native int c_setOption(int optID, int value);
    

    @Override
    public Object getOption(int optID) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public void startTimeMeasurement() {
        c_startTimeMeasurement();
    }
    public native void c_startTimeMeasurement();
    
    public long getTiming() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    public native void c_getTiming();
    
    /**
     * Callback function for TimingOutputStream
     * @param ar The data to be send
     */
    public void write(byte[] ar) {
        c_write(ar);
    }
    public native int c_write(byte[] ar);
    
    /**
     * Callback function for TimingInputStream
     * @param ar The array that is filled with data
     * @return The amount of bytes read
     */
    public int read(byte[] ar) {
        return c_read(ar);
    }
    public native int c_read(byte[] ar);
    
    /**
     * Callback function for TimingInputStream
     * @return A single byte read from the socket
     */
    public int read() {
        return c_read_no_param();
    }
    public native int c_read_no_param();
    
}
