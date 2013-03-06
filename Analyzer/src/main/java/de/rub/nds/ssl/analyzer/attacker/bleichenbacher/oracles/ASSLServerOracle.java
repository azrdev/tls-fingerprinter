package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
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
    private TLS10HandshakeWorkflow workflow;
    /**
     * TLS protocol version.
     */
    public static EProtocolVersion PROTOCOL_VERSION = EProtocolVersion.TLS_1_0;
    private String host;
    private int port;
    private byte[] encPMStoCheck;
    private boolean oracleResult = false;
    private Logger logger = Logger.getRootLogger();

    public ASSLServerOracle(final String serverAddress, final int serverPort)
            throws SocketException {
        this.host = serverAddress;
        this.port = serverPort;
    }

    public static PublicKey fetchServerPublicKey(final String serverHost,
            final int serverPort) throws
            GeneralSecurityException, IOException {
        // everyone is our friend - let's trust the whole world
        TrustManager trustManager = new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs,
                    String authType) {
            }

            @Override
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

    void executeWorkflow(final byte[] msg, final ESupportedSockets socketType)
            throws OracleException {
        try {
            setWorkflow(new TLS10HandshakeWorkflow(socketType));
            getWorkflow().addObserver(this,
                    TLS10HandshakeWorkflow.EStates.CLIENT_HELLO);
            getWorkflow().addObserver(this,
                    TLS10HandshakeWorkflow.EStates.CLIENT_KEY_EXCHANGE);
            getWorkflow().
                    addObserver(this, TLS10HandshakeWorkflow.EStates.ALERT);

            getWorkflow().connectToTestServer(this.getHost(), this.getPort());
            numberOfQueries++;

            setEncPMStoCheck(msg);
            getWorkflow().start();
            getWorkflow().closeSocket();
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
                this.publicKey = (RSAPublicKey) fetchServerPublicKey(this.
                        getHost(), this.getPort());
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

    /**
     * @return the logger
     */
    public Logger getLogger() {
        return logger;
    }

    /**
     * @param logger the logger to set
     */
    public void setLogger(final Logger logger) {
        this.logger = logger;
    }

    /**
     * @return the oracleResult
     */
    public boolean oracleResult() {
        return oracleResult;
    }

    /**
     * @param oracleResult the oracleResult to set
     */
    protected void setOracleResult(boolean oracleResult) {
        this.oracleResult = oracleResult;
    }

    /**
     * @return the host
     */
    public String getHost() {
        return host;
    }

    /**
     * @param host the host to set
     */
    public void setHost(final String host) {
        this.host = host;
    }

    /**
     * @return the port
     */
    public int getPort() {
        return port;
    }

    /**
     * @param port the port to set
     */
    public void setPort(final int port) {
        this.port = port;
    }

    /**
     * @return the encPMStoCheck
     */
    public byte[] getEncPMS() {
        return encPMStoCheck;
    }

    /**
     * @param msg the encPMStoCheck to set
     */
    public void setEncPMStoCheck(final byte[] msg) {
        this.encPMStoCheck = new byte[msg.length];
        System.arraycopy(msg, 0, getEncPMS(), 0, msg.length);
    }

    /**
     * @return the workflow
     */
    public TLS10HandshakeWorkflow getWorkflow() {
        return workflow;
    }

    /**
     * @param workflow the workflow to set
     */
    public void setWorkflow(TLS10HandshakeWorkflow workflow) {
        this.workflow = workflow;
    }
}
