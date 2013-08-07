package de.rub.nds.research.timingsocket;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import javax.imageio.IIOException;

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

    /**
     * This class implements callbacks to
     *
     * @TimingSocketImpl.
     */
    private class TimingOutputStream extends OutputStream {

        @Override
        public void close() throws IOException {
            tsi.c_close();
        }

        @Override
        /**
         * We flush with every write in the C functions, so we don't need this
         * Java method (I guess...).
         */
        public void flush() throws IOException {
        }

        @Override
        public void write(byte[] bytes, int i, int i1) throws IOException {
            new Exception("").printStackTrace();
            throw new UnsupportedOperationException("Not supported yet.");
        }
        TimingSocketImpl tsi;

        /**
         * TimingOutputStream only works with an instance of TimingSocketImpl.
         */
        private TimingOutputStream() {
        }

        public TimingOutputStream(TimingSocketImpl tsi) {
            this.tsi = tsi;
        }

        @Override
        /**
         * Please do not use this method. Use
         *
         * @write(byte[]) instead and only send atomic writes, i.e. do not split
         * a request across multiple writes. This would currently screw up the
         * timing measurements.
         */
        public void write(int i) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void write(byte[] ar) throws IOException {
            try {
                tsi.write(ar);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * This class implements callbacks to
     *
     * @TimingSocketImpl.
     */
    private class TimingInputStream extends InputStream {

        @Override
        public int available() throws IOException {
            int ret = -1;
            try {
                ret = tsi.available();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return ret;
        }

        @Override
        public void close() throws IOException {
            tsi.close();
        }

        @Override
        public synchronized void mark(int i) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean markSupported() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public synchronized void reset() throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public long skip(long l) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        TimingSocketImpl tsi;

        private TimingInputStream() {
        }

        public TimingInputStream(TimingSocketImpl tsi) {
            this.tsi = tsi;
        }

        /**
         * This method never returns zero, because this case is handled in C
         * land. It returns -1 if EOF.
         *
         *
         * @param ar
         * @return
         * @throws IOException The socket is somehow dead. In this case the C
         * lib should write some debug information to stdout and return -2
         * (which is a special return value).
         */
        @Override
        public int read(byte[] ar) throws IOException {
            int ret = read(ar, 0, ar.length);

            return ret;
        }

        @Override
        public int read() throws IOException {
            byte[] tmpByte = new byte[1];
            int r = read(tmpByte, 0, tmpByte.length);

            int ret;
            if (r == -1) {
                ret = -1;
            } else {
                // (-127, 128)  wird zu (0, 255)
                ret = tmpByte[0] & 0xff;
            }
            return ret;
        }

        @Override
        public int read(byte[] ar, int off, int len) throws IOException {
            int ret = tsi.read(ar, off, len);

            if (ret == -2) {
                throw new IOException("C land detected serious errors -> Socket is dead.");
            }

            return ret;
        }
    }

    static {
        String lib = new File("").getAbsolutePath() + "/../TimingSocket/src/main/java/libnativecode.dylib";
        System.out.println("Attempting to load " + lib);
        System.load(lib);
    }
    private int file_desc;
    private OutputStream os;
    private InputStream is;

    @Override
    public void create(boolean stream) throws IOException {
        if (stream == false) {
            throw new UnsupportedOperationException("Datagram socket not supported yet. Use stream==true.");
        }

        file_desc = c_create(stream);

        if (file_desc < 0) {
            throw new IOException("Cannot create socket.");
        }

        os = new TimingOutputStream(this);
        is = new TimingInputStream(this);
    }

    private native int c_create(boolean stream);

    @Override
    public void connect(String host, int port) throws IOException {
        int ret = c_connect(file_desc, host, port);

        if (ret != 0) {
            throw new IOException("Cannot connect socket.");
        }
    }

    private native int c_connect(int socket, String host, int port);

    @Override
    protected void connect(InetAddress address, int port) throws IOException {
        String host = address.getCanonicalHostName();
        connect(host, port);
    }

    @Override
    protected void connect(SocketAddress address, int timeout) throws
            IOException {
        String host = ((InetSocketAddress) address).getHostName();
        int port = ((InetSocketAddress) address).getPort();
        connect(host, port);
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

    /**
     *
     * @return 1 if there is data available, 0 if there is no data available.
     * @throws IOException
     */
    @Override
    protected int available() throws IOException {
        return c_available();
    }

    private native int c_available();

    @Override
    protected void close() throws IOException {
        c_close();
    }

    private native int c_close();

    @Override
    protected void sendUrgentData(int data) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setOption(int optID, Object value) throws SocketException {
        int ret = -1;
        switch (optID) {
            case SocketOptions.SO_LINGER:
            case SocketOptions.SO_TIMEOUT:
                int value_int = (Integer) value;
                ret = c_setOption(optID, value_int);
                break;
            default:
                throw new UnsupportedOperationException("Option ID " + Integer.toHexString(optID) + " not supported yet.");
        }

        if (ret != 0) {
            throw new SocketException("Could not set option");
        }
    }

    private native int c_setOption(int optID, int value);

    @Override
    public Object getOption(int optID) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * This function retrieves the measured time.
     *
     * @return The measured response time from sending the last byte of the
     * request to retrieving the first byte of the response. The unit of
     * measurement is CPU clock ticks. If the return value is 0, an error
     * occurred.
     */
    public long getTiming() {
        return c_getTiming();
    }

    private native long c_getTiming();

    /**
     * Callback function for TimingOutputStream
     *
     * @param ar The data to be send
     */
    private void write(byte[] ar) {
        /*
         * Always start the timing measurement because
         * we tag each and every single message 
         * roundtrip.
         */
        int len = c_write(ar);
        if (ar.length != len) {
            throw new RuntimeException("sent less data than I wanted to send.");
        }
    }

    private native int c_write(byte[] ar);

    /**
     * Callback function for TimingInputStream
     *
     * @param ar The array that is filled with data
     * @return The amount of bytes read
     */
    private int read(byte[] ar) {
        return c_read(ar);
    }

    private native int c_read(byte[] ar);

    public static void startMeasurement() {
        c_start_measurement();
    }

    private static native void c_start_measurement();

    /**
     * Callback function for TimingInputStream
     *
     * @param ar The array that is filled with data
     * @param offset The offset where to start the read in the stream
     * @param length The amount of bytes to be read
     * @return The amount of bytes read
     */
    private int read(byte[] ar, int offset, int length) {
        int ret = c_read_off(ar, offset, length);
        if (ret == 0) {
            System.out.println("EOF read()");
            ret = -1;
        }
        return ret;
    }

    private native int c_read_off(byte[] ar, int offset, int length);

    /**
     * Callback function for TimingInputStream
     *
     * @return A single byte read from the socket
     */
    private int read() {
        int ret = c_read_no_param();

        /*
         * If the read() of C returns 0, we reached EOF. In this case, we
         * return -1.
         * If the read() of C returns -1, an error occured. In this case, we
         * throw an exception.
         */
        switch (ret) {
            case 0:
                // EOF
                return -1;
            case -1:
                // Error!
                throw new RuntimeException("Read error.");
            default:
                return ret;
        }

    }

    private native int c_read_no_param();
}
