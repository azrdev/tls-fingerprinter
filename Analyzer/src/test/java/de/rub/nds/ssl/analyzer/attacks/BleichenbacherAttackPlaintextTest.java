package de.rub.nds.ssl.analyzer.attacks;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.BleichenbacherCrypto12;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.ATestOracle;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.StdPlainOracle;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
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

    @Test(enabled = true)
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
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        SecureRandom sr = new SecureRandom();

        int iterations = 50;
        long queriesBleichenbacher = 0;
        long queriesBardou = 0;

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

            AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                    ATestOracle.OracleType.TTT, cipher.getBlockSize());

            BleichenbacherCrypto12 attacker1 = new BleichenbacherCrypto12(message,
                    oracle, true);
            attacker1.attack();
            queriesBardou += oracle.getNumberOfQueries();
            
            oracle = new StdPlainOracle(keyPair.getPublic(),
                    ATestOracle.OracleType.TTT, cipher.getBlockSize());

            Bleichenbacher attacker2 = new Bleichenbacher(message,
                    oracle, true);
            attacker2.attack();
            queriesBleichenbacher += oracle.getNumberOfQueries();
        }
        
        logger.info("Bleichenbacher -- Queries total: " + queriesBleichenbacher );
        logger.info("Bardou         -- Queries total: " + queriesBardou );
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
