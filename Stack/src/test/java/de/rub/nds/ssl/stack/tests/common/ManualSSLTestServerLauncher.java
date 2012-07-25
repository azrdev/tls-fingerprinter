package de.rub.nds.ssl.stack.tests.common;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Manual Launcher for SSL Testserver.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 8, 2012
 */
public class ManualSSLTestServerLauncher {

    /**
     * Protocol short name.
     */
    private static String protocolShortName = "TLS";
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Server key store.
     */
    private static final String PATH_TO_JKS = "server.jks";
    /**
     * Pass word for server key store.
     */
    private static final String JKS_PASSWORD = "server";
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException,
            KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        SSLServer sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                protocolShortName, PORT, PRINT_INFO);
        Thread sslServerThread = new Thread(sslServer);
        sslServerThread.start();
    }
}
