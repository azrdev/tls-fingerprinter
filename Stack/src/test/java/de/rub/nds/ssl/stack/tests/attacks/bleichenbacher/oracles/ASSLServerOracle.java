package de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.oracles;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.exceptions.OracleException;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.tests.trace.MessageTrace;
import de.rub.nds.ssl.stack.tests.workflows.ObservableBridge;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import javax.net.ssl.*;
import org.apache.log4j.Logger;
import org.apache.log4j.lf5.LogLevel;

/**
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * September 14, 2012
 */
public abstract class ASSLServerOracle extends AOracle implements Observer {

    /**
     * Handshake workflow to observe.
     */
    TLS10HandshakeWorkflow workflow;
    /**
     * TLS protocol version.
     */
    EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    String host;
    int port;
    byte[] encPMStoCheck;
    boolean oracleResult = false;
    Logger logger = Logger.getRootLogger();

    public ASSLServerOracle(final String serverAddress, final int serverPort)
            throws SocketException {
        this.host = serverAddress;
        this.port = serverPort;
    }

    public static PublicKey fetchServerPublicKey(String serverHost,
            int serverPort) throws
            GeneralSecurityException, IOException {
        // everyone is our friend - let's trust the whole world
        TrustManager trustManager = new X509TrustManager() {

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs,
                    String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs,
                    String authType) {
            }
        };

        // get a socket and extract the certificate
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, new TrustManager[]{trustManager}, null);
        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(
                serverHost, serverPort);
        sslSocket.setEnabledCipherSuites(buildRSACipherSuiteList(
                sslSocket.getEnabledCipherSuites()));
        sslSocket.startHandshake();
        SSLSession sslSession = sslSocket.getSession();
        Certificate[] peerCerts = sslSession.getPeerCertificates();

        return peerCerts[0].getPublicKey();
    }
    
    void exectuteWorkflow(final byte[] msg) throws OracleException {
        try {
            workflow = new TLS10HandshakeWorkflow(false);
            workflow.addObserver(this, 
                    TLS10HandshakeWorkflow.EStates.CLIENT_HELLO);
            workflow.addObserver(this, 
                    TLS10HandshakeWorkflow.EStates.CLIENT_KEY_EXCHANGE);
            workflow.addObserver(this, TLS10HandshakeWorkflow.EStates.ALERT);

            workflow.connectToTestServer(this.host, this.port);

            numberOfQueries++;

            encPMStoCheck = msg;
            workflow.start();
            workflow.closeSocket();
        } catch (SocketException e) {
            throw new OracleException(e.getLocalizedMessage(), e, 
                    LogLevel.DEBUG);
        }
    }

    int computeBlockSize() {
        byte[] tmp = ((RSAPublicKey) getPublicKey()).getModulus().toByteArray();
        int result = tmp.length;
        int remainder = tmp.length % 8;

        if (remainder > 0 && tmp[0] == 0x0) {
            // extract signing byte if present
            byte[] tmp2 = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, tmp2, 0, tmp2.length);
            tmp = tmp2;
            remainder = tmp.length % 8;
            result = tmp.length;
        }

        while (remainder > 0) {
            result++;
            remainder = result % 8;
        }

        return result;
    }

    @Override
    public int getBlockSize() {
        if (this.blockSize == 0) {
            this.blockSize = computeBlockSize();
        }

        return this.blockSize;
    }

    @Override
    public PublicKey getPublicKey() {
        if (this.publicKey == null) {
            try {
                this.publicKey = (RSAPublicKey) fetchServerPublicKey(this.host,
                        this.port);
            } catch (GeneralSecurityException ex) {
                ex.printStackTrace();
            } catch (ConnectException e) {
                e.printStackTrace();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        return this.publicKey;
    }

    private static String[] buildRSACipherSuiteList(String[] suites) {
        List<String> cs = new ArrayList<String>(10);

        for (String suite : suites) {
            if (suite.contains("RSA")) {
                cs.add(suite);
            }
        }
        return cs.toArray(new String[cs.size()]);
    }

}
