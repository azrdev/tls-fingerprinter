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
import java.util.Collections;
import java.util.LinkedList;
import javax.crypto.Cipher;
import junit.framework.Assert;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class BleichenbacherOracleTest {

    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();

    @Test(enabled = false)
    public final void testJSSEOracle()
            throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                        ATestOracle.OracleType.JSSE, 128);
        
        byte[] msg = new byte[127];
        for(int i=0; i<msg.length; i++) {
            msg[i] = 0x01;
        }
        // start with 0x02, no 0x00 byte given
        msg[0] = 0x02;
        
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
        
        // set the second last byte to 0x00
        msg[msg.length-2] = 0x00;        
        Assert.assertTrue(oracle.checkPKCSConformity(msg));
        
        // insert an extra 0x00 byte in the middle
        msg[20] = 0x00;
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
    }
    
    @Test(enabled = true)
    public final void testXMLENCOracle() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                        ATestOracle.OracleType.XMLENC, 128);
        
        byte[] msg = new byte[127];
        for(int i=0; i<msg.length; i++) {
            msg[i] = 0x01;
        }
        // start with 0x02, no 0x00 byte given
        msg[0] = 0x02;
        
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
        
        // set the 17th byte from behind to 0x00
        msg[msg.length-17] = 0x00; 
        Assert.assertTrue(oracle.checkPKCSConformity(msg));
        
        // set the 25th byte from behind to 0x00
        msg[msg.length-25] = 0x00;        
        Assert.assertTrue(oracle.checkPKCSConformity(msg));
        
        // set the 33th byte from behind to 0x00
        msg[msg.length-33] = 0x00;        
        Assert.assertTrue(oracle.checkPKCSConformity(msg));
        
        msg[34] = 0x00;
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
        
        // insert an extra 0x00 byte in the middle
        msg[50] = 0x00;
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
    }
    
    @Test(enabled = true)
    public final void testGnuTLSOracle() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        AOracle oracle = new StdPlainOracle(keyPair.getPublic(),
                        ATestOracle.OracleType.GNU_TLS, 128);
        
        byte[] msg = new byte[127];
        for(int i=0; i<msg.length; i++) {
            msg[i] = 0x01;
        }
        // start with 0x02, no 0x00 byte given
        msg[0] = 0x02;
        
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
        
        // set the 49th byte from behind to 0x00
        msg[msg.length-49] = 0x00; 
        Assert.assertTrue(oracle.checkPKCSConformity(msg));
        
        // set the 50th byte from behind to 0x00 (it should fail since the 
        // PMS would be 49 bytes long
        msg[50] = 0x00;
        Assert.assertFalse(oracle.checkPKCSConformity(msg));
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
