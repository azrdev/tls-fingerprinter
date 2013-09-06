package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.ASSLServerOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.JSSE16Oracle;
import de.rub.nds.ssl.stack.Utility;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Performs Bleichenbacher Tests against a server with a 1024 bit long key
 *
 * @author Juraj Somorovsky
 * @version 0.1
 *
 * Feb 8, 2013
 */
public class BleichenbacherPossibleTest {

//    private static final String HOST = "localhost";
    private static final String HOST = "localhost";
    private static final int PORT = 51624;
    /**
     * Plain PKCS message
     */
    private static final byte[] plainPKCS = new byte[]{
        (byte) 0x00, (byte) 0x02, (byte) 0xf5, (byte) 0xa7, (byte) 0x9f,
        (byte) 0xcd, (byte) 0xb1, (byte) 0x27, (byte) 0xf9, (byte) 0x39,
        (byte) 0x15, (byte) 0x21, (byte) 0x49, (byte) 0x71, (byte) 0x65,
        (byte) 0x25, (byte) 0x07,
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
        (byte) 0x01};
    private PublicKey publicKey;
    private byte[] encPMS;
    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();

    private static KeyStore loadKeyStore(final String keyStorePath,
            final String keyStorePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStorePath), keyStorePassword.
                toCharArray());

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

    @Test(enabled = false, priority = 2)
    public void sslTriggerOracleTest() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle(HOST, PORT);

        TestVector[] vectors;
        byte[] enc;

        int counter = 0;

        // valid
        logger.info("\n\t++++Start Test:  valid message++++");
        enc = encryptHelper(plainPKCS, publicKey);
        jsseOracle.checkPKCSConformity(enc);
        counter++;

        //test invalid PKCS1 messages
        vectors = getInvalidPKCS1messages();
        for (int i = 0; i < vectors.length; i++) {
            enc = encryptHelper(vectors[i].message, publicKey);
            logger.info(vectors[i].description);
            logger.info("Message plain: " + 
                    Utility.bytesToHex(vectors[i].message));
            jsseOracle.checkPKCSConformity(enc);
            counter++;
        }

        System.out.println("counter: " + counter);
    }
    
    @Test(enabled = false, priority = 2)
    public void sslSingleRequest() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle(HOST, PORT);

        // valid
        byte[] enc = encryptHelper(plainPKCS, publicKey);
        jsseOracle.checkPKCSConformity(enc);
    }

    /**
     *
     * @return invalid PKCS1 messages
     */
    private TestVector[] getInvalidPKCS1messages() {
        TestVector[] vectors = new TestVector[9];

        byte[][] invalidPKCS1messages = new byte[9][plainPKCS.length];
        for (int i = 0; i < invalidPKCS1messages.length; i++) {
            invalidPKCS1messages[i] = Arrays.copyOf(plainPKCS, plainPKCS.length);
            vectors[i] = new TestVector();
        }
        invalidPKCS1messages[0][1] = 0x01;
        vectors[0].message = invalidPKCS1messages[0];
        vectors[0].description = "\n\t++++Start Test:  set the second byte to"
                + " 0x01 (should be 0x02)++++";

        invalidPKCS1messages[1][1] = 0x00;
        vectors[1].message = invalidPKCS1messages[1];
        vectors[1].description = "\n\t++++Start Test:  set the second byte to "
                + "0x00 (should be 0x02)++++";
        
        invalidPKCS1messages[2][2] = 0x00;
        vectors[2].message = invalidPKCS1messages[2];
        vectors[2].description = "\n\t++++Start Test:  set the third byte to "
                + "0x00 (must not be 0x00)++++";
        
        invalidPKCS1messages[3][10] = 0x00;
        vectors[3].message = invalidPKCS1messages[3];
        vectors[3].description = "\n\t++++Start Test:  invalid PMS length "
                + "(longer PMS)++++";
        
        invalidPKCS1messages[4][plainPKCS.length - 50] = 0x00;
        vectors[4].message = invalidPKCS1messages[4];
        vectors[4].description = "\n\t++++Start Test:  invalid PMS length "
                + "(longer PMS)++++";

        invalidPKCS1messages[5][plainPKCS.length - 49] = 0x01;
        invalidPKCS1messages[5][plainPKCS.length - 43] = 0x00;
        vectors[5].message = invalidPKCS1messages[5];
        vectors[5].description = "\n\t++++Start Test:  invalid PMS length "
                + "(shorter PMS)++++";

        invalidPKCS1messages[6][plainPKCS.length - 49] = 0x01;
        vectors[6].message = invalidPKCS1messages[6];
        vectors[6].description = "\n\t++++Start Test:  no 0x00++++";

        invalidPKCS1messages[7][plainPKCS.length - 48] = (byte) 255;
        vectors[7].message = invalidPKCS1messages[7];
        vectors[7].description = "\n\t++++Start Test:  invalid version "
                + "number++++";

        invalidPKCS1messages[8][plainPKCS.length - 49] = 0x01;
        invalidPKCS1messages[8][2] = 0x00;
        vectors[8].message = invalidPKCS1messages[8];
        vectors[8].description = "\n\t++++Start Test:  0x00 on the third "
                + "position, no 0x00 in the middle++++";
        
        return vectors;
    }

    @BeforeMethod
    protected void printMethodBanner(Method method) throws Exception {
        String testName = method.getName();
        logger.info("++++Start Test (" + testName + ")++++");
    }

    @AfterMethod
    protected void printEndOfMethodBanner(Method method) throws Exception {
        String testName = method.getName();
        logger.info("++++End of Test (" + testName + ")++++");
        logger.info("------------------------------");
    }

    /**
     * Initialize logging properties and the 2048 bit long key
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
        logger.info("##################################");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
        Security.addProvider(new BouncyCastleProvider());

        try {
//            String keyName = "1024_rsa";
//            String keyPassword = "password";
//            KeyStore ks = loadKeyStore("server.jks", "password");
//            publicKey = ks.getCertificate(keyName).getPublicKey();
            publicKey = ASSLServerOracle.fetchServerPublicKey(HOST, PORT);

            encPMS = encryptHelper(plainPKCS, publicKey);
//        } catch (UnrecoverableKeyException ex) {
//            logger.error(ex.getMessage(), ex);
        } catch (GeneralSecurityException ex) {
            java.util.logging.Logger.getLogger(BleichenbacherPossibleTest.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (KeyStoreException ex) {
//            logger.error(ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
//        } catch (CertificateException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (NoSuchAlgorithmException ex) {
//            logger.error(ex.getMessage(), ex);
        }
    }

    private class TestVector {

        byte[] message;
        String description;
    }
}
