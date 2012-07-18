/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles.AOracle;
import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles.ATestOracle;
import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles.StandardPlaintextOracle;
import java.security.*;
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
        keyPairGenerator.initialize(1024);
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
        
        AOracle oracle = new StandardPlaintextOracle(keyPair.getPublic(),
                ATestOracle.OracleType.TTT, cipher.getBlockSize());

        BleichenbacherAttackCrypto attacker = new BleichenbacherAttackCrypto(message,
                oracle, 500,  false);
        attacker.attack();

        logger.info("------------------------------");
    }
    
    /**
     * Initialize logging properties
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
    }
}
