package de.rub.nds.ssl.stack.tests.attacktests;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.RsaUtil;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.BleichenbacherParameters;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.ssl.stack.tests.common.SSLServerHandler;
import de.rub.nds.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.tests.trace.MessageTrace;
import de.rub.nds.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow.EStates;
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
    private TLS10HandshakeWorkflow workflow;
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
    private BleichenbacherParameters params = new BleichenbacherParameters();
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
                        protocolVersion.getId(), false,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Wrong protocol version in PreMasterSecret",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0.getId(), false,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Invalid protocol version in PreMasterSecret",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        new byte[]{(byte) 0xff, (byte) 0xff}, false,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Seperate byte not 0x00",
                        new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersion.getId(), false,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Mode changed (first two bytes)",
                        new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersion.getId(), false,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Zero byte at first position in padding",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion.getId(), true,
                        SSLTestUtils.POSITIONS.FIRST, 0},
                    {"Zero byte in the middle of the padding string",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion.getId(), true,
                        SSLTestUtils.POSITIONS.MIDDLE, 0},
                    {"Zero byte at the end of the padding string",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion.getId(), true,
                        SSLTestUtils.POSITIONS.LAST, 0},
                    {"Zero byte at custom position of the padding string",
                        new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersion.getId(), true,
                        null, 5}};
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
            final byte[] version, final boolean changePadding,
            final SSLTestUtils.POSITIONS position, final Integer anyPosition)
            throws IOException {
        logger.info("++++ Start Test No." + counter + " (" + desc + ") ++++");
        workflow = new TLS10HandshakeWorkflow(false);
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.info(
                    "Test Server: " + TestConfiguration.HOST
                    + ":" + TestConfiguration.PORT);
        }
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");
        params.setMode(mode);
        params.setSeparate(separate);
        params.setProtocolVersion(version);
        params.setChangePadding(changePadding);
        params.setPosition(position);
        params.setAnyPosition(anyPosition);
        params.setIdentifier(EFingerprintIdentifier.BleichenbacherAttack);
        params.setDescription(desc);

        workflow.start();

        //analyze the handshake trace
//        AFingerprintAnalyzer analyzer = new TestHashAnalyzer(params);
//        analyzer.analyze(workflow.getTraceList());

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
        MessageTrace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageTrace) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    MessageBuilder builder = new MessageBuilder();
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                    ClientHello clientHello =
                            builder.createClientHello(EProtocolVersion.TLS_1_0.
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
                    pms.setProtocolVersion(protocolVersion);
                    byte[] encodedPMS = pms.encode(false);
                    if (params.getProtocolVersion() != null) {
                        byte[] version = params.getProtocolVersion();
                        System.arraycopy(version, 0, encodedPMS, 0,
                                version.length);
                    }
                    logger.debug("PreMasterSecret: " + Utility.bytesToHex(
                            encodedPMS));
                    //encrypt the PreMasterSecret
                    EncPreMasterSecret encPMS =
                            new EncPreMasterSecret(pk);
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
                    utils.setSeparateByte(params.getSeparate());
                    utils.setMode(params.getMode());
                    //generate the PKCS#1 padding string
                    byte[] padding = utils.createPaddingString(utils.
                            getPaddingLength());
                    if (params.isChangePadding()) {
                        if (params.getPosition() != null) {
                            padding = utils.changeByteArray(padding,
                                    params.getPosition(), (byte) 0x00);
                            utils.setPadding(padding);
                        } else if (params.getAnyPosition() > 0) {
                            padding = utils.changeArbitraryPos(padding,
                                    params.getAnyPosition(), (byte) 0x00);
                            utils.setPadding(padding);
                        }
                    }
                    //put the PKCS#1 pieces together
                    byte[] clear = utils.buildPKCS1Msg(encodedPMS);
                    //compute c = m^e mod n (RSA encryption)
                    byte[] ciphertext = RsaUtil.pubOp(clear, rsaPK);
                    encPMS.setEncryptedPreMasterSecret(ciphertext);
                    cke.setExchangeKeys(encPMS);

                    trace.setOldRecord(trace.getCurrentRecord());
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
        logger.info("##################################");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
//        System.setProperty("javax.net.debug", "all");
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
