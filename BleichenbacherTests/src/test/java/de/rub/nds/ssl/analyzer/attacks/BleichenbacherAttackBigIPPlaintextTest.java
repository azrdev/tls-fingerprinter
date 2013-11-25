package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherBigIP;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.ATestOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.StdPlainOracle;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collections;
import java.util.LinkedList;
import javax.crypto.Cipher;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackBigIPPlaintextTest {

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
    private static final byte[] plainPKCS2048 = new byte[]{
        (byte) 0x00, (byte) 0x02, (byte) 0x05, (byte) 0xa7, (byte) 0x9f,
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
        (byte) 0x9b, (byte) 0xf5,
        // for 2048 bits uncomment
        (byte) 0xc3, (byte) 0xc3, (byte) 0xaf,
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
        (byte) 0x1f, (byte) 0x27, (byte) 0x9f, (byte) 0x5d, (byte) 0x0,
        (byte) 0x39, (byte) 0x1b,
        (byte) 0x01,
        (byte) 0x03, (byte) 0x01,
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

    @Test(enabled = true)
    public final void testBleichenbacherAttack()
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        byte[] message = plainPKCS2048;

        AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                ATestOracle.OracleType.BigIP, 256);

        BleichenbacherBigIP attacker = new BleichenbacherBigIP(message,
                oracle, true);
        attacker.attack();
    }

    /**
     * Last Result:
     *
     * WARN [main] 25 Nov 2013 15:40:58,571 - Bleichenbacher
     *
     * WARN [main] 25 Nov 2013 15:40:58,572 - Queries total: 49558159
     *
     * WARN [main] 25 Nov 2013 15:40:58,572 - Mean: 99116
     *
     * WARN [main] 25 Nov 2013 15:40:58,572 - Median: 4734
     *
     * WARN [main] 25 Nov 2013 15:40:58,573 - Min: 3784
     *
     * WARN [main] 25 Nov 2013 15:40:58,573 - Max: 1189896
     *
     * WARN [main] 25 Nov 2013 15:40:58,573 - Badly computed: 45
     * (the 45 ciphertexts are badly computed. Their interval computation
     * was imprecise and should be done better...however, who cares...)
     *
     */
    @Test(enabled = false)
    public final void testBleichenbacherAttackPerformance()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        logger.warn("starting attacks");

        int iterations = 500;
        int badlyComputed = 0;
        LinkedList<Long> queriesBleichenbacher = new LinkedList<Long>();

        for (int i = 0; i < iterations; i++) {
            logger.warn("iter " + i);
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            SecureRandom sr = new SecureRandom();
            byte[] plainBytes = new byte[48];
            sr.nextBytes(plainBytes);
            byte[] cipherBytes;

            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipherBytes = cipher.doFinal(plainBytes);

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] message = cipher.doFinal(cipherBytes);

            AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                    ATestOracle.OracleType.BigIP, cipher.getBlockSize());

            BleichenbacherBigIP attacker = new BleichenbacherBigIP(
                    message, oracle, true);
            try {
                attacker.attack();
                queriesBleichenbacher.add(oracle.getNumberOfQueries());
            } catch (RuntimeException e) {
                queriesBleichenbacher.add((long) 1000000);
                badlyComputed++;
            }
            System.out.println("Queries " + i + " : " + oracle.
                    getNumberOfQueries());
        }
        Collections.sort(queriesBleichenbacher);

        logger.info("---------------------");
        long queries;

        logger.warn("Bleichenbacher");
        queries = sumList(queriesBleichenbacher);
        logger.warn("Queries total: " + queries);
        logger.warn("Mean: " + (queries / iterations));
        logger.warn("Median: " + queriesBleichenbacher.get(iterations / 2));
        logger.warn("Min: " + queriesBleichenbacher.get(0));
        logger.warn("Max:       " + queriesBleichenbacher.get(iterations - 1));
        logger.warn("Badly computed (my implementation is not perfect and in case"
                + " there are more intervals for a solution, the algorithm "
                + " computes a wrong interval): " + badlyComputed);
    }

    private static long sumList(LinkedList<Long> list) {
        long ret = 0;
        for (Long l : list) {
            ret += l;
        }
        return ret;
    }
}
