package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.ATestOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.StdPlainOracle;
import de.rub.nds.ssl.stack.Utility;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Random;
import javax.crypto.Cipher;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Plain PKCS 1024 bit
     */
    private static final byte[] plainPKCS1024 = new byte[]{
        (byte) 2, (byte) 113, (byte) 89, (byte) -75, (byte) 59, (byte) -45, 
        (byte) 27, (byte) -61, (byte) -9, (byte) -21, (byte) 27, (byte) -1, 
        (byte) -5, (byte) 121, (byte) 93, (byte) -51, (byte) -43, (byte) 95, 
        (byte) 37, (byte) -7, (byte) 75, (byte) -109, (byte) 97, (byte) -29, 
        (byte) -53, (byte) -29, (byte) 105, (byte) -13, (byte) -9, (byte) 37, 
        (byte) 39, (byte) 87, (byte) -73, (byte) 113, (byte) -105, (byte) -21, 
        (byte) -29, (byte) 125, (byte) 11, (byte) -123, (byte) 15, (byte) 61, 
        (byte) -93, (byte) -87, (byte) 117, (byte) 111, (byte) 109, (byte) 111,
        (byte) 89, (byte) 79, (byte) 49, (byte) 9, (byte) 47, (byte) 51,
        (byte) -47, (byte) -33, (byte) 63, (byte) 91, (byte) 117, (byte) 49, 
        (byte) -23, (byte) -73, (byte) -51, (byte) -31, (byte) -71, (byte) 51, 
        (byte) -59, (byte) 59, (byte) -41, (byte) -11, (byte) -65, (byte) 7, 
        (byte) 61, (byte) 73, (byte) 65, (byte) -69, (byte) -73, (byte) -121, 
        (byte) 0, (byte) 3, (byte) 1, (byte) -127, (byte) -85, (byte) -25, 
        (byte) 13, (byte) -57, (byte) -89, (byte) -91, (byte) 89, (byte) 15, 
        (byte) -89, (byte) 109, (byte) -83, (byte) 15, (byte) -87, (byte) 37, 
        (byte) -105, (byte) -65, (byte) -123, (byte) 71, (byte) 11, (byte) -51,
        (byte) -101, (byte) 33, (byte) 27, (byte) 29, (byte) 123, (byte) -19,
        (byte) -41, (byte) -15, (byte) 29, (byte) 23, (byte) 103, (byte) 79, 
        (byte) 7, (byte) -109, (byte) 77, (byte) -115, (byte) -19, (byte) 57, 
        (byte) 109, (byte) 51, (byte) 21, (byte) 29, (byte) 111, (byte) -11, 
        (byte) -109};
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

    @Test(enabled = false)
    public final void testBleichenbacherAttack()
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        SecureRandom sr = new SecureRandom();
        byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
        sr.nextBytes(plainBytes);
        byte[] cipherBytes;

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        cipherBytes = cipher.doFinal(plainBytes);

        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] message = cipher.doFinal(cipherBytes);

        AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                ATestOracle.OracleType.JSSE, cipher.getBlockSize());

        Bleichenbacher attacker = new Bleichenbacher(message,
                oracle, true);
        attacker.attack();
    }

    /**
     * TODO Test runs too long.
     *
     * @throws Exception
     */
    @Test(enabled = false)
    public final void testBleichenbacherAttackPerformance()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);

        logger.warn("starting attacks");

        int iterations = 1000;
        LinkedList<Long> queriesBleichenbacher = new LinkedList<Long>();

        LinkedList<Long> queriesBardou = new LinkedList<Long>();

        for (int i = 0; i < iterations; i++) {
            logger.warn("iter " + i);
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            SecureRandom sr = new SecureRandom();
            byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
            sr.nextBytes(plainBytes);
            byte[] cipherBytes;

            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipherBytes = cipher.doFinal(plainBytes);

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] message = cipher.doFinal(cipherBytes);

            AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                    ATestOracle.OracleType.JSSE, cipher.getBlockSize());

            BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(
                    message,
                    oracle, true, 5000);
            attacker1.attack();
            queriesBardou.add(oracle.getNumberOfQueries());
            System.out.println("Queries " + i + " : " + oracle.
                    getNumberOfQueries());

//            oracle = new StdPlainOracle(keyPair.getPublic(),
//                    ATestOracle.OracleType.JSSE, cipher.getBlockSize());
//
//            Bleichenbacher attacker2 = new Bleichenbacher(message,
//                    oracle, true);
//            attacker2.attack();
//            queriesBleichenbacher.add(oracle.getNumberOfQueries());
        }
        Collections.sort(queriesBardou);
//        Collections.sort(queriesBleichenbacher);

        logger.info("---------------------");
        long queries;

//        logger.warn("Bleichenbacher");
//        queries = sumList(queriesBleichenbacher);
//        logger.warn("Queries total: " + queries);
//        logger.warn("Mean: " + (queries / iterations));
//        logger.warn("Median: " + queriesBleichenbacher.get(iterations / 2));
//        logger.warn("Min: " + queriesBleichenbacher.get(0));
//        logger.warn("Max:       " + queriesBleichenbacher.get(iterations - 1));

        logger.warn("Bardou");
        queries = sumList(queriesBardou);
        logger.warn("Queries total: " + queries);
        logger.warn("Mean: " + (queries / iterations));
        logger.warn("Median: " + queriesBardou.get(iterations / 2));
        logger.warn("Min: " + queriesBardou.get(0));
        logger.warn("Max:       " + queriesBardou.get(iterations - 1));
    }

    /**
     * Test performance of the trimmers method in the Bardou's attack by setting
     * different types of trimmers.
     *
     * @throws Exception
     */
    @Test(enabled = false)
    public final void testBleichenbacherAttackPerformanceTrimmers()
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        SecureRandom sr = new SecureRandom();

        int iterations = 50;
        long[] queriesBleichenbacher = {0, 0, 0, 0, 0};

        int[] trimmNummbers = {500, 1500, 2500, 4000, 6000};

        for (int i = 0; i < iterations; i++) {
            byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
            sr.nextBytes(plainBytes);
            byte[] cipherBytes;

            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipherBytes = cipher.doFinal(plainBytes);

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] message = cipher.doFinal(cipherBytes);

            for (int j = 0; j < trimmNummbers.length; j++) {

                AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                        ATestOracle.OracleType.JSSE, cipher.getBlockSize());

                BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(
                        message,
                        oracle, true, trimmNummbers[j]);
                attacker1.attack();
                queriesBleichenbacher[j] += oracle.getNumberOfQueries();
            }
        }

        for (int j = 0; j < trimmNummbers.length; j++) {
            logger.info("Bleichenbacher -- Queries total for trimm nummber "
                    + trimmNummbers[j] + ": " + queriesBleichenbacher[j]);
        }
    }

    @Test(enabled = false)
    public final void testBleichenbacherAttackPerformanceXMLEnc()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);

        logger.warn("starting attacks");

        int iterations = 100;
        LinkedList<Long> queriesBardou = new LinkedList<Long>();

        for (int i = 0; i < iterations; i++) {
            logger.warn("iter " + i);
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            SecureRandom sr = new SecureRandom();
            byte[] plainBytes = new byte[16];
            sr.nextBytes(plainBytes);
            byte[] cipherBytes;

            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipherBytes = cipher.doFinal(plainBytes);

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] message = cipher.doFinal(cipherBytes);

            AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                    ATestOracle.OracleType.XMLENC, cipher.getBlockSize());

            BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(
                    message,
                    oracle, true, 5000);
            attacker1.attack();
            queriesBardou.add(oracle.getNumberOfQueries());
            System.out.println("Queries " + i + " : " + oracle.
                    getNumberOfQueries());
        }
        Collections.sort(queriesBardou);

        logger.info("---------------------");
        long queries;

        logger.warn("Bardou");
        queries = sumList(queriesBardou);
        logger.warn("Queries total: " + queries);
        logger.warn("Mean: " + (queries / iterations));
        logger.warn("Median: " + queriesBardou.get(iterations / 2));
        logger.warn("Min: " + queriesBardou.get(0));
        logger.warn("Max:       " + queriesBardou.get(iterations - 1));
    }

    @Test(enabled = true)
    public final void testBleichenbacherAttackStaticKey()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = loadKeyStore(new FileInputStream("1024.jks"),
                "password");

        byte[] plainBytes = plainPKCS1024;

        AOracle oracle = new StdPlainOracle(ks.getCertificate("1024_rsa").
                getPublicKey(), ATestOracle.OracleType.FFT, 128);

        Bleichenbacher attacker = new Bleichenbacher(plainBytes,
                oracle, true);
        attacker.attack();
    }

    @Test(enabled = true)
    public final void testFindGoodKey()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = loadKeyStore(new FileInputStream("1024.jks"),
                "password");

        Random random = new SecureRandom();

        while (true) {
            byte[] plainBytes = new byte[127];
            random.nextBytes(plainBytes);
            for (int i = 0; i < plainBytes.length; i++) {
                plainBytes[i] |= 1;
            }
            plainBytes[0] = 2;
            plainBytes[plainBytes.length - 49] = 0;
            plainBytes[plainBytes.length - 48] = 3;
            plainBytes[plainBytes.length - 47] = 1;

            AOracle oracle = new StdPlainOracle(ks.getCertificate("1024_rsa").
                    getPublicKey(), ATestOracle.OracleType.FFT, 128);

            Bleichenbacher attacker = new Bleichenbacher(
                    plainBytes, oracle, true);
            attacker.attack();

            long x = oracle.getNumberOfQueries();
            System.out.println("number of queries: " + x);
            if (x < 15000) {
                System.out.println("plain bytes: ");
                System.out.println(Utility.bytesToHex(plainBytes));

                Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, ks.getCertificate("1024_rsa").
                        getPublicKey());
                byte[] cipherBytes = cipher.doFinal(plainBytes);

                System.out.println("cipher bytes: ");
                System.out.println(Utility.bytesToHex(cipherBytes));

                System.out.println("byte[] cipherPKCS = new byte[]{");
                for (int j = 0; j < cipherBytes.length; j++) {
                    System.out.print("(byte) " + cipherBytes[j]);
                    if (j != cipherBytes.length - 1) {
                        System.out.print(", ");
                    }
                }
                System.out.println("}");

                System.out.println("byte[] plainPKCS = new byte[]{");
                for (int j = 0; j < plainBytes.length; j++) {
                    System.out.print("(byte) " + plainBytes[j]);
                    if (j != plainBytes.length - 1) {
                        System.out.print(", ");
                    }
                }
                System.out.println("}");

                return;
            }
        }
    }

    private static long sumList(LinkedList<Long> list) {
        long ret = 0;
        for (Long l : list) {
            ret += l;
        }
        return ret;
    }

    private static KeyStore loadKeyStore(final InputStream keyStoreStream,
            final String keyStorePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(keyStoreStream, keyStorePassword.toCharArray());

        return ks;
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
     * Initialize logging properties
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
        logger.info("##################################");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
    }
}
