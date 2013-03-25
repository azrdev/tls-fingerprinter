package de.rub.nds.tinytlssocket;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.log4j.Category;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;

/**
 * SSL Test Server.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 7, 2012
 */
public final class TLSServer extends Thread {

    private final byte[] MESSAGE = "Welcome to the TinyTLSServer".getBytes();
    private int listenPort;
    private SSLContext sslContext;
    private boolean shutdown;
    private static final int TIMEOUT = 500;
    private Logger logger;

    public TLSServer(final String keyStorePath, final String password,
            final String protocol, final int port)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {

        KeyStore keyStore = loadKeyStore(keyStorePath);
        init(keyStore, password, protocol, port);
    }

    public TLSServer(final KeyStore keyStore, final String password,
            final String protocol, final int port) throws KeyStoreException,
            IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        init(keyStore, password, protocol, port);
    }

    private KeyStore loadKeyStore(final String keyStorePath) throws
            KeyStoreException, FileNotFoundException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStorePath), null);

        return ks;
    }

    private Logger setupLogger() {
        Logger result = Logger.getRootLogger();

        // make sure everything sent to System.err is logged
        System.setErr(new PrintStream(
                new LoggingOutputStream(Category.getRoot(), Priority.WARN),
                true));

        // make sure everything sent to System.out is logged
        System.setOut(new PrintStream(
                new LoggingOutputStream(Category.getRoot(), Priority.INFO),
                true));

        // activate handshake debug logging
        System.setProperty("javax.net.debug", "ssl,handshake");

        return result;
    }

    private void init(final KeyStore keyStore, final String password,
            final String protocol, final int port) throws KeyStoreException,
            IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        this.logger = setupLogger();
        this.sslContext = setupContext(keyStore, password, protocol);
        this.listenPort = port;

        logger.info("|| SSL Server successfully initialized!");
    }

    private static SSLContext setupContext(final KeyStore keyStore,
            final String password, final String protocol) throws
            NoSuchAlgorithmException, KeyStoreException, KeyManagementException,
            UnrecoverableKeyException {
        SSLContext result;

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                "SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        result = SSLContext.getInstance(protocol);
        result.init(keyManagers, trustManagers, null);

        return result;
    }

    @Override
    public void run() {
        Socket socket = null;
        ServerSocket serverSocket = null;
        try {
            serverSocket = setupSocket();
            logger.info("|| waiting for connections...");
            while (!shutdown) {
                try {
                    socket = serverSocket.accept();
                    logger.info("|| connection available");

                    TLSPlaintext applicationResponse = new TLSPlaintext(
                            EProtocolVersion.TLS_1_0);
                    applicationResponse.setFragment(MESSAGE);
                    socket.getOutputStream().write(
                            applicationResponse.encode(false));
                } catch (SocketTimeoutException e) {
                    // ignore - it will fill your logs!
                    //logger.debug(e);
                    continue;
                } catch (IOException e) {
                    logger.error(e);
                    // keep on going after any errors! 
                    // dirrrrrty, don't do this at home!
                }
            }
        } catch (IOException e) {
            logger.error(e);
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                logger.error(e);
                // silently ignore
            }

            logger.info("|| shutdown complete");
        }
    }

    private ServerSocket setupSocket() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory =
                sslContext.getServerSocketFactory();
        ServerSocket result =
                serverSocketFactory.createServerSocket(listenPort);

        result.setSoTimeout(TIMEOUT);
        result.setReuseAddress(true);
        logger.info("|| presetup successful");

        return result;
    }

    public void shutdown() {
        this.shutdown = true;
        logger.info("|| shutdown signal received");
    }
}
