package de.rub.nds.ssl.analyzer.removeMe;

import de.rub.nds.ssl.analyzer.attacks.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacks.bleichenbacher.oracles.TimingOracle;
import java.net.SocketException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TimingOracleTest {
/**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Test Server Thread.
     */
    private Thread sslServerThread;
    /**
     * Test SSL Server.
     */
    private SSLServer sslServer;
    /**
     * Server key store.
     */
    private static final String PATH_TO_JKS = "server.jks";
    /**
     * Pass word for server key store.
     */
    private static final String JKS_PASSWORD = "server";
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Encrypted PKCS message
     */
    private static final byte[] encryptedPKCSCorrect = new byte[]{
        (byte) 0x5b, (byte) 0xa7, (byte) 0x3d, (byte) 0x6d, (byte) 0xa0,
        (byte) 0xdf, (byte) 0x9e, (byte) 0x52, (byte) 0x55, (byte) 0x99,
        (byte) 0x7c, (byte) 0x56, (byte) 0x2a, (byte) 0xf7, (byte) 0x5b,
        (byte) 0xa0, (byte) 0x31, (byte) 0x66, (byte) 0xb8, (byte) 0x54,
        (byte) 0x9f, (byte) 0x07, (byte) 0x1f, (byte) 0x7a, (byte) 0x20,
        (byte) 0x72, (byte) 0x36, (byte) 0x21, (byte) 0x9f, (byte) 0xda,
        (byte) 0xc0, (byte) 0xf6, (byte) 0xf5, (byte) 0xc1, (byte) 0x10,
        (byte) 0x58, (byte) 0x5c, (byte) 0x65, (byte) 0x36, (byte) 0x59,
        (byte) 0xb8, (byte) 0xf2, (byte) 0x53, (byte) 0x7a, (byte) 0x31,
        (byte) 0x25, (byte) 0x3e, (byte) 0xc0, (byte) 0x98, (byte) 0x7d,
        (byte) 0xb6, (byte) 0x4d, (byte) 0xd3, (byte) 0x5f, (byte) 0xb5,
        (byte) 0xcc, (byte) 0x5f, (byte) 0xa2, (byte) 0xdb, (byte) 0x12,
        (byte) 0x6a, (byte) 0xae, (byte) 0x84, (byte) 0xdf, (byte) 0xaf,
        (byte) 0x77, (byte) 0x6f, (byte) 0x53, (byte) 0xee, (byte) 0xf5,
        (byte) 0xaf, (byte) 0x34, (byte) 0x07, (byte) 0xbc, (byte) 0x23,
        (byte) 0x1c, (byte) 0xd5, (byte) 0x5a, (byte) 0xdf, (byte) 0x4d,
        (byte) 0x2a, (byte) 0x9d, (byte) 0xc1, (byte) 0x92, (byte) 0x71,
        (byte) 0x30, (byte) 0xc7, (byte) 0xc5, (byte) 0x59, (byte) 0x4f,
        (byte) 0x12, (byte) 0x98, (byte) 0xc1, (byte) 0x21, (byte) 0x66,
        (byte) 0xf3, (byte) 0xe2, (byte) 0xf7, (byte) 0xe1, (byte) 0x33,
        (byte) 0xfe, (byte) 0xbe, (byte) 0x26, (byte) 0x05, (byte) 0x64,
        (byte) 0x05, (byte) 0x1f, (byte) 0x95, (byte) 0xee, (byte) 0x9d,
        (byte) 0xad, (byte) 0x16, (byte) 0x29, (byte) 0x64, (byte) 0x0f,
        (byte) 0x89, (byte) 0x2c, (byte) 0x3b, (byte) 0xa6, (byte) 0x8b,
        (byte) 0x6c, (byte) 0xe7, (byte) 0x05, (byte) 0x66, (byte) 0x10,
        (byte) 0xe2, (byte) 0xc2, (byte) 0x80, (byte) 0x9c, (byte) 0xcd,
        (byte) 0xd8, (byte) 0xd0, (byte) 0x0b, (byte) 0xfe, (byte) 0x90,
        (byte) 0xe7, (byte) 0xda, (byte) 0x16, (byte) 0x01, (byte) 0x04,
        (byte) 0x07, (byte) 0x2c, (byte) 0x6d, (byte) 0xbe, (byte) 0xec,
        (byte) 0xf2, (byte) 0xf7, (byte) 0xbe, (byte) 0x52, (byte) 0x74,
        (byte) 0xd5, (byte) 0x79, (byte) 0xcd, (byte) 0x72, (byte) 0xf2,
        (byte) 0x7d, (byte) 0x8d, (byte) 0x77, (byte) 0x22, (byte) 0x52,
        (byte) 0x3b, (byte) 0xb8, (byte) 0x35, (byte) 0x9d, (byte) 0xf8,
        (byte) 0x4d, (byte) 0xca, (byte) 0x38, (byte) 0x70, (byte) 0xed,
        (byte) 0x76, (byte) 0x71, (byte) 0x65, (byte) 0xa0, (byte) 0x87,
        (byte) 0x55, (byte) 0x9f, (byte) 0xfb, (byte) 0x22, (byte) 0xe7,
        (byte) 0x1b, (byte) 0x6e, (byte) 0x54, (byte) 0xbb, (byte) 0xaf,
        (byte) 0xdd, (byte) 0x30, (byte) 0x97, (byte) 0x2f, (byte) 0xa0,
        (byte) 0x5d, (byte) 0x09, (byte) 0x69, (byte) 0x06, (byte) 0x55,
        (byte) 0x20, (byte) 0x0c, (byte) 0x28, (byte) 0x3a, (byte) 0xe8,
        (byte) 0xcd, (byte) 0x63, (byte) 0xf3, (byte) 0xf4, (byte) 0xfa,
        (byte) 0x90, (byte) 0xf2, (byte) 0x00, (byte) 0xba, (byte) 0x46,
        (byte) 0x27, (byte) 0x5c, (byte) 0x89, (byte) 0x89, (byte) 0x79,
        (byte) 0x5c, (byte) 0x57, (byte) 0x37, (byte) 0xd8, (byte) 0x8f,
        (byte) 0xd5, (byte) 0x74, (byte) 0x22, (byte) 0x2e, (byte) 0x31,
        (byte) 0x26, (byte) 0xb2, (byte) 0xb0, (byte) 0xe7, (byte) 0x39,
        (byte) 0x7d, (byte) 0x7d, (byte) 0xf6, (byte) 0x6c, (byte) 0xde,
        (byte) 0x0c, (byte) 0xb5, (byte) 0xd2, (byte) 0x86, (byte) 0x84,
        (byte) 0x2e, (byte) 0x64, (byte) 0xa8, (byte) 0xb9, (byte) 0x28,
        (byte) 0xc1, (byte) 0x13, (byte) 0x6b, (byte) 0x93, (byte) 0x93,
        (byte) 0xd2, (byte) 0xb3, (byte) 0xfd, (byte) 0x7d, (byte) 0xaa,
        (byte) 0xe3};
    
    /**
     * Encrypted PKCS message
     */
    private static final byte[] encryptedPKCSWrong = new byte[]{
        (byte) 0x5c, (byte) 0xa7, (byte) 0x3d, (byte) 0x6d, (byte) 0xa0,
        (byte) 0xdf, (byte) 0x9e, (byte) 0x52, (byte) 0x55, (byte) 0x99,
        (byte) 0x7c, (byte) 0x56, (byte) 0x2a, (byte) 0xf7, (byte) 0x5b,
        (byte) 0xa0, (byte) 0x31, (byte) 0x66, (byte) 0xb8, (byte) 0x54,
        (byte) 0x9f, (byte) 0x07, (byte) 0x1f, (byte) 0x7a, (byte) 0x20,
        (byte) 0x72, (byte) 0x36, (byte) 0x21, (byte) 0x9f, (byte) 0xda,
        (byte) 0xc0, (byte) 0xf6, (byte) 0xf5, (byte) 0xc1, (byte) 0x10,
        (byte) 0x58, (byte) 0x5c, (byte) 0x65, (byte) 0x36, (byte) 0x59,
        (byte) 0xb8, (byte) 0xf2, (byte) 0x53, (byte) 0x7a, (byte) 0x31,
        (byte) 0x25, (byte) 0x3e, (byte) 0xc0, (byte) 0x98, (byte) 0x7d,
        (byte) 0xb6, (byte) 0x4d, (byte) 0xd3, (byte) 0x5f, (byte) 0xb5,
        (byte) 0xcc, (byte) 0x5f, (byte) 0xa2, (byte) 0xdb, (byte) 0x12,
        (byte) 0x6a, (byte) 0xae, (byte) 0x84, (byte) 0xdf, (byte) 0xaf,
        (byte) 0x77, (byte) 0x6f, (byte) 0x53, (byte) 0xee, (byte) 0xf5,
        (byte) 0xaf, (byte) 0x34, (byte) 0x07, (byte) 0xbc, (byte) 0x23,
        (byte) 0x1c, (byte) 0xd5, (byte) 0x5a, (byte) 0xdf, (byte) 0x4d,
        (byte) 0x2a, (byte) 0x9d, (byte) 0xc1, (byte) 0x92, (byte) 0x71,
        (byte) 0x30, (byte) 0xc7, (byte) 0xc5, (byte) 0x59, (byte) 0x4f,
        (byte) 0x12, (byte) 0x98, (byte) 0xc1, (byte) 0x21, (byte) 0x66,
        (byte) 0xf3, (byte) 0xe2, (byte) 0xf7, (byte) 0xe1, (byte) 0x33,
        (byte) 0xfe, (byte) 0xbe, (byte) 0x26, (byte) 0x05, (byte) 0x64,
        (byte) 0x05, (byte) 0x1f, (byte) 0x95, (byte) 0xee, (byte) 0x9d,
        (byte) 0xad, (byte) 0x16, (byte) 0x29, (byte) 0x64, (byte) 0x0f,
        (byte) 0x89, (byte) 0x2c, (byte) 0x3b, (byte) 0xa6, (byte) 0x8b,
        (byte) 0x6c, (byte) 0xe7, (byte) 0x05, (byte) 0x66, (byte) 0x10,
        (byte) 0xe2, (byte) 0xc2, (byte) 0x80, (byte) 0x9c, (byte) 0xcd,
        (byte) 0xd8, (byte) 0xd0, (byte) 0x0b, (byte) 0xfe, (byte) 0x90,
        (byte) 0xe7, (byte) 0xda, (byte) 0x16, (byte) 0x01, (byte) 0x04,
        (byte) 0x07, (byte) 0x2c, (byte) 0x6d, (byte) 0xbe, (byte) 0xec,
        (byte) 0xf2, (byte) 0xf7, (byte) 0xbe, (byte) 0x52, (byte) 0x74,
        (byte) 0xd5, (byte) 0x79, (byte) 0xcd, (byte) 0x72, (byte) 0xf2,
        (byte) 0x7d, (byte) 0x8d, (byte) 0x77, (byte) 0x22, (byte) 0x52,
        (byte) 0x3b, (byte) 0xb8, (byte) 0x35, (byte) 0x9d, (byte) 0xf8,
        (byte) 0x4d, (byte) 0xca, (byte) 0x38, (byte) 0x70, (byte) 0xed,
        (byte) 0x76, (byte) 0x71, (byte) 0x65, (byte) 0xa0, (byte) 0x87,
        (byte) 0x55, (byte) 0x9f, (byte) 0xfb, (byte) 0x22, (byte) 0xe7,
        (byte) 0x1b, (byte) 0x6e, (byte) 0x54, (byte) 0xbb, (byte) 0xaf,
        (byte) 0xdd, (byte) 0x30, (byte) 0x97, (byte) 0x2f, (byte) 0xa0,
        (byte) 0x5d, (byte) 0x09, (byte) 0x69, (byte) 0x06, (byte) 0x55,
        (byte) 0x20, (byte) 0x0c, (byte) 0x28, (byte) 0x3a, (byte) 0xe8,
        (byte) 0xcd, (byte) 0x63, (byte) 0xf3, (byte) 0xf4, (byte) 0xfa,
        (byte) 0x90, (byte) 0xf2, (byte) 0x00, (byte) 0xba, (byte) 0x46,
        (byte) 0x27, (byte) 0x5c, (byte) 0x89, (byte) 0x89, (byte) 0x79,
        (byte) 0x5c, (byte) 0x57, (byte) 0x37, (byte) 0xd8, (byte) 0x8f,
        (byte) 0xd5, (byte) 0x74, (byte) 0x22, (byte) 0x2e, (byte) 0x31,
        (byte) 0x26, (byte) 0xb2, (byte) 0xb0, (byte) 0xe7, (byte) 0x39,
        (byte) 0x7d, (byte) 0x7d, (byte) 0xf6, (byte) 0x6c, (byte) 0xde,
        (byte) 0x0c, (byte) 0xb5, (byte) 0xd2, (byte) 0x86, (byte) 0x84,
        (byte) 0x2e, (byte) 0x64, (byte) 0xa8, (byte) 0xb9, (byte) 0x28,
        (byte) 0xc1, (byte) 0x13, (byte) 0x6b, (byte) 0x93, (byte) 0x93,
        (byte) 0xd2, (byte) 0xb3, (byte) 0xfd, (byte) 0x7d, (byte) 0xaa,
        (byte) 0xe3};

    
    @Test(enabled = false)
    public final void testTimingOracle()
            throws OracleException, SocketException {
        logger.info("++++Start Test++++");

        TimingOracle to = new TimingOracle(HOST, PORT);
        to.trainOracle(encryptedPKCSCorrect, encryptedPKCSWrong);
        
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

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
        try {
//            System.setProperty("javax.net.debug", "ssl");
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        try {
            if (sslServer != null) {
                sslServer.shutdown();
                sslServer = null;
            }

            if (sslServerThread != null) {
                sslServerThread.interrupt();
                sslServerThread = null;
            }


            Thread.currentThread().sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
