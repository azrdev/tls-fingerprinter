package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.*;

/**
 * Standard Bleichenbacher oracle.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 18, 2012
 */
public class JSSEOracle implements IOracle {

    private final RSAPublicKey publicKey;
    private long numberOfQueries;
    private String host;
    private int port;

    public JSSEOracle(final String serverAddress, final int serverPort)
            throws SSLException {
        this.host = serverAddress;
        this.port = serverPort;

        try {
            publicKey = (RSAPublicKey) fetchServerPublicKey(this.host,
                    this.port);
        } catch (GeneralSecurityException ex) {
            throw new SSLException(ex);
        } catch (IOException ex) {
            throw new SSLException(ex);
        }
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
    public long getNumberOfQueries() {
        return numberOfQueries;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        boolean result = false;
        numberOfQueries++;

        return result;
    }

    @Override
    public int getBlockSize() {
        return publicKey.getModulus().divide(BigInteger.valueOf(8)).intValue();
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }
    
    private static String[] buildRSACipherSuiteList(String[] suites) {
        List<String> cs = new ArrayList<String>(10);
        
        for(String suite : suites) {
            if(suite.contains("RSA")) {
                cs.add(suite);
            }
        }
        return cs.toArray(new String[cs.size()]);
    }
}
