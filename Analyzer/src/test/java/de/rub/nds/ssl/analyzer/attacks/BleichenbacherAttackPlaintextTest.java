package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
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
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeClass;
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

        logger.info("++++Start Test No. 1 (Bleichenbacher Plaintext)++++");

        Bleichenbacher attacker = new Bleichenbacher(message,
                oracle, true);
        attacker.attack();

        logger.info("------------------------------");
    }

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

            BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(message,
                    oracle, true, 5000);
            attacker1.attack();
            queriesBardou.add(oracle.getNumberOfQueries());
            System.out.println("Queries " + i + " : " + oracle.getNumberOfQueries());

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

        System.out.println("---------------------");
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

                BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(message,
                        oracle, true, trimmNummbers[j]);
                attacker1.attack();
                queriesBleichenbacher[j] += oracle.getNumberOfQueries();
            }
        }

        for (int j = 0; j < trimmNummbers.length; j++) {
            logger.info("Bleichenbacher -- Queries total for trimm nummber "
                    + trimmNummbers[j] + ": " + queriesBleichenbacher[j]);
        }
        logger.info("------------------------------");
    }

    private static long sumList(LinkedList<Long> list) {
        long ret = 0;
        for (Long l : list) {
            ret += l;
        }
        return ret;
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
