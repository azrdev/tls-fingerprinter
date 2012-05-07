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

import de.rub.nds.research.ssl.stack.protocols.commons.DataRecord;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.*;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * <DESCRIPTION> @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 7, 2012
 */
public class SSLServer extends Thread {

    private final byte[] MESSAGE = "Welcome to the SSL Test Server".getBytes();
    private int port;
    private SSLContext sslContext;
    private ServerSocket serverSocket;
    private boolean shutdown;

    public SSLServer(String path, String password, String protocol, int port)
            throws FileNotFoundException,
            KeyStoreException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            UnrecoverableKeyException,
            KeyManagementException {
        FileInputStream fis = new FileInputStream(path);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(fis, password.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                "SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, null, null);

        this.port = port;
        System.out.println("|| SSL Server successfully initialized!");
    }

    public void run() {
        Socket socket = null;
        try {
            preSetup();
            while (!shutdown) {
                try {
                    System.out.println(
                            "|| waiting for connections...");
                    socket = serverSocket.accept();
                    System.out.println(
                            "|| connection available");
                    DataRecord applicationResponse =
                            new DataRecord(EProtocolVersion.TLS_1_0,
                            MESSAGE);
                    // TODO it is necessary to be able to send unecrypted data!
                    applicationResponse.setEncryptedData(MESSAGE);
                    socket.getOutputStream().write(
                            applicationResponse.encode(false));
                } catch (SocketTimeoutException e) {
                    // ignore
                    continue;
                } 
            }
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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
            System.out.println("|| shutdown complete");
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.
                getServerSocketFactory();
        serverSocket = serverSocketFactory.createServerSocket(port);
        serverSocket.setSoTimeout(5000);
        System.out.println("|| presetup successful");
    }

    public void shutdown() {
        this.shutdown = true;
        System.out.println("|| shutdown signal received");
    }
}
