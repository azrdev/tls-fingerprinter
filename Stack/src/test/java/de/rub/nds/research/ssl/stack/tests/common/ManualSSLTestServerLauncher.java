/*
 * Copyright 2011 Sec2 Consortium
 * 
 * This source code is part of the "Sec2" project and as this remains property
 * of the project partners. Content and concepts have to be treated as
 * CONFIDENTIAL. Publication or partly disclosure without explicit written
 * permission is prohibited.
 * For details on "Sec2" and its contributors visit
 * 
 *        http://www.sec2.org
 */
package de.rub.nds.research.ssl.stack.tests.common;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 *  <DESCRIPTION> @author Christopher Meyer - christopher.meyer@rub.de
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
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException,
            KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        SSLServer sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                protocolShortName, PORT);
        Thread sslServerThread = new Thread(sslServer);
        sslServerThread.start();
    }
}
