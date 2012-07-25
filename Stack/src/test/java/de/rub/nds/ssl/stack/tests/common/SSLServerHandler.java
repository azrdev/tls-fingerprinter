package de.rub.nds.ssl.stack.tests.common;

/**
 * Start/Stop the SSL test server.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 07, 2012
 */
public class SSLServerHandler {

    /**
     * Test Server Thread.
     */
    private Thread sslServerThread;
    /**
     * Test SSL Server.
     */
    private SSLServer sslServer;
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
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Test port.
     */
    private static final int PORT = 10443;

    /**
     * Start the SSL test server.
     */
    public void startTestServer() {
        try {
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Stop the SSL test server.
     */
    public void shutdownTestServer() {
        try {
            if (sslServer != null) {
                sslServer.shutdown();
                sslServer = null;
            }

            if (sslServerThread != null) {
                sslServerThread.interrupt();
                sslServerThread = null;
            }
            Thread.interrupted();

            Thread.currentThread().sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
