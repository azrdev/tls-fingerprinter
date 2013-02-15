package de.rub.nds.ssl.analyzer.removeMe;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.*;
import java.security.cert.CertificateException;
import javax.net.ssl.*;

/**
 * SSL Test Server.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 7, 2012
 */
public class SSLServer extends Thread {

    private final byte[] MESSAGE = "Welcome to the SSL Test Server".getBytes();
    private int listenPort;
    private SSLContext sslContext;
    private ServerSocket serverSocket;
    private boolean shutdown;
    private boolean printInfo;
    private static final int TIMEOUT = 500;

    public SSLServer(final KeyStore keyStore, final String password,
            final String protocol, final int port, final boolean printStateInfo)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                "SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.
                getInstance(
                "SunX509");
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers, null);
                
        this.listenPort = port;
        this.printInfo = printStateInfo;
        if (printInfo) {
            System.out.println("|| SSL Server successfully initialized!");
        }
    }

    public void run() {
        Socket socket = null;
        try {
            preSetup();
            while (!shutdown) {
                try {
                    if (printInfo) {
                        System.out.println("|| waiting for connections...");
                    }
                    socket = serverSocket.accept();
                    if (printInfo) {
                        System.out.println("|| connection available");
                    }
                    TLSPlaintext applicationResponse = new TLSPlaintext(
                            EProtocolVersion.TLS_1_0);
                    applicationResponse.setFragment(MESSAGE);
                    socket.getOutputStream().write(
                            applicationResponse.encode(false));
                } catch (SocketTimeoutException e) {
                    // ignore
                    continue;
                } catch (Exception e) {
                    // keep on going after any errors! 
                    // dirrrrrty, don't do this at home!
                }
            }
        } catch (SocketException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                    socket = null;
                }
                if (serverSocket != null) {
                    serverSocket.close();
                    serverSocket = null;
                }
            } catch (IOException e) {
                // silently ignore
            }
            if (printInfo) {
                System.out.println("|| shutdown complete");
            }
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.
                getServerSocketFactory();
        serverSocket = serverSocketFactory.createServerSocket(listenPort);
        
        serverSocket.setSoTimeout(TIMEOUT);
        serverSocket.setReuseAddress(true);
        if (printInfo) {
            System.out.println("|| presetup successful");
        }
    }

    public void shutdown() {
        this.shutdown = true;
        if (printInfo) {
            System.out.println("|| shutdown signal received");
        }
    }
}
