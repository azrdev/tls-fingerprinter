package de.rub.nds.research.ssl.stack.tests.attacktests;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.RsaUtil;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.BleichenbacherParameters;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLServerHandler;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Observable;
import java.util.Observer;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.*;

/**
 * Test for Bleichenbacher attack.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 12, 2012
 */
public class BleichenbacherTest implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private SSLTestUtils utils = new SSLTestUtils();
    /**
     * TLS protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Bleichenbacher test parameters.
     */
    private BleichenbacherParameters parameters = new BleichenbacherParameters();
    /**
     * Handler to start/stop a test server.
     */
    private SSLServerHandler serverHandler = new SSLServerHandler();

    /**
     * Test parameters for the Bleichenbacher Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "bleichenbacher")
    public Object[][] createData1() {
        return new Object[][]{
                    {"OK case",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion, false,
                        SSLTestUtils.POSITIONS.FIRST},
                    {"Wrong protocol version in PreMasterSecret",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false,
                        SSLTestUtils.POSITIONS.FIRST},
                    {"Seperate byte not 0x00",
                        new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersion, false,
                        SSLTestUtils.POSITIONS.FIRST},
                    {"Mode changed (first two bytes)",
                        new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersion, false,
                        SSLTestUtils.POSITIONS.FIRST},
                    {"Zero byte at first position in padding",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion, true,
                        SSLTestUtils.POSITIONS.FIRST},
                    {"Zero byte in the middle of the padding string",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion, true,
                        SSLTestUtils.POSITIONS.MIDDLE},
                    {"Zero byte at the end of the padding string",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion, true,
                        SSLTestUtils.POSITIONS.LAST},};
    }

    /**
     * Test if Bleichenbacher attack is possible.
     *
     * @param mode First two bytes of PKCS#1 message which defines the op-mode
     * @param separate Separate byte between padding and data in PKCS#1 message
     * @param version Protocol version
     * @param changeByteArray True if padding should be changed
     * @param position Position where padding is changed
     * @throws IOException
     */
    @Test(enabled = true, dataProvider = "bleichenbacher", invocationCount = 1)
    public final void testBleichenbacherPossible(String desc,
            final byte[] mode, final byte[] separate,
            final EProtocolVersion version, final boolean changePadding,
            final SSLTestUtils.POSITIONS position)
            throws IOException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new SSLHandshakeWorkflow(false);
        workflow.connectToTestServer(HOST, PORT);
        logger.info("Test Server: " + HOST + ":" + PORT);
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");

        parameters.setMode(mode);
        parameters.setSeparate(separate);
        parameters.setProtocolVersion(version);
        parameters.setChangePadding(changePadding);
        parameters.setPosition(position);

        workflow.start();
        logger.info("------------------------------");
        this.counter++;
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    MessageBuilder builder = new MessageBuilder();
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                    ClientHello clientHello = builder.createClientHello(EProtocolVersion.TLS_1_0.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            protocolVersion,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms = new PreMasterSecret(protocolVersion);
                    workflow.setPreMasterSecret(pms);
                    pms.setProtocolVersion(parameters.getProtocolVersion());
                    byte[] encodedPMS = pms.encode(false);

                    //encrypt the PreMasterSecret
                    EncryptedPreMasterSecret encPMS =
                            new EncryptedPreMasterSecret(pk);
                    BigInteger mod = null;
                    RSAPublicKey rsaPK = null;
                    if (pk != null && pk instanceof RSAPublicKey) {
                        rsaPK = (RSAPublicKey) pk;
                        mod = rsaPK.getModulus();
                    }

                    int modLength = 0;
                    if (mod != null) {
                        modLength = mod.bitLength() / 8;
                    }
                    /*
                     * set the padding length of the PKCS#1 padding string (it
                     * is [<Modulus length> - <Data length> -3])
                     */
                    utils.setPaddingLength((modLength - encodedPMS.length - 3));
                    utils.setSeparateByte(parameters.getSeparate());
                    utils.setMode(parameters.getMode());
                    //generate the PKCS#1 padding string
                    byte[] padding = utils.createPaddingString(utils.
                            getPaddingLength());
                    if (parameters.isChangePadding()) {
                        padding = utils.changeByteArray(padding,
                                parameters.getPosition(), (byte) 0x00);
                        utils.setPadding(padding);
                    }
                    //put the PKCS#1 pieces together
                    byte[] clear = utils.buildPKCS1Msg(encodedPMS);
                    //compute c = m^e mod n (RSA encryption)
                    byte[] ciphertext = RsaUtil.pubOp(clear, rsaPK);
                    encPMS.setEncryptedPreMasterSecret(ciphertext);
                    cke.setExchangeKeys(encPMS);

                    trace.setCurrentRecord(cke);
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Initialize logging properties
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
//            System.setProperty("javax.net.debug", "ssl");
        serverHandler.startTestServer();
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
        serverHandler.shutdownTestServer();
    }
}
