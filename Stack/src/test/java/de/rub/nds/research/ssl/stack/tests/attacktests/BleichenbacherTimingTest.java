package de.rub.nds.research.ssl.stack.tests.attacktests;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLServer;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import static java.lang.Thread.sleep;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.*;
import sun.security.rsa.RSACore;

/**
 * Test for Bleichenbacher attack.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.2 Apr 12, 2012
 */
public class BleichenbacherTimingTest implements Observer {

    /**
     * Client hello message.
     */
    private ClientHello clientHello;
    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private SSLTestUtils utils = new SSLTestUtils();
    /**
     * TLS protocol version of the record frame.
     */
    private EProtocolVersion protocolVersionRecord = EProtocolVersion.TLS_1_0;
    /**
     * TLS protocol version of the premaster secret.
     */
    private EProtocolVersion protocolVersionPMS = EProtocolVersion.TLS_1_0;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Separate byte between padding and data in PKCS#1 message.
     */
    private byte[] separateByte;
    /**
     * First two bytes of PKCS#1 message which defines the op-mode.
     */
    private byte[] pkcsMode;
    /**
     * Signalizes if padding should be changed.
     */
    private boolean chgPadding;
    /**
     * Position in padding to change.
     */
    private SSLTestUtils.POSITIONS positionOfPaddingChange;
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
     * Overall delays.
     */
    private final long[] delays = new long[NUMBER_OF_REPETIIONS];
    /**
     * Number of repetitions.
     */
    private static final int NUMBER_OF_REPETIIONS = 100;
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;
    /*
     * Flags if MAC should be invalidated
     */
    private boolean destroyMAC = false;
    /**
     * Flags if the TimingSocket for accurate timing should be used
     */
    private static final boolean ACCURATE_TIMING = false;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();

    /**
     * Test parameters for the Bleichenbacher Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "bleichenbacher")
    public Object[][] createData1() {
        return new Object[][]{
                    // ok case
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST, "OK",
                        false},
                    // wrong protocol version in PreMasterSecret
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Wrong protocol version in PreMasterSecret",
                        false},
                    // seperate byte is not 0x00
                    {new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Seperate byte is not 0x00",
                        false},
                    // mode changed
                    {new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Mode changed to 0x01",
                        false},
                    // zero byte at the first position of the padding
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Zero byte at the first position of the padding",
                        false},
                    // zero byte in the middle of the padding string
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.MIDDLE,
                        "Zero byte in the middle of the padding string",
                        false},
                    // zero byte at the end of the padding string
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.LAST,
                        "Zero byte at the end of the padding string",
                        false},
                    // ok case, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "MSG ok, MAC tampered",
                        true},
                    // wrong protocol version in PreMasterSecret, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Wrong protocol version in PreMasterSecret, "
                        + "MAC tampered", true},
                    // seperate byte is not 0x00
                    {new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Seperate byte is not 0x00, MAC tampered",
                        true},
                    // mode changed, MAC tampered
                    {new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Mode changed to 0x01, MAC tampered",
                        true},
                    // zero byte at the first position of the padding, 
                    // MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.FIRST,
                        "Zero byte at the first position of the padding, "
                        + "MAC tampered", true},
                    // zero byte in the middle of the padding string, 
                    // MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.MIDDLE,
                        "Zero byte in the middle of the padding string, "
                        + "MAC tampered", true},
                    // zero byte at the end of the padding string, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        SSLTestUtils.POSITIONS.LAST,
                        "Zero byte at the end of the padding string, "
                        + "MAC tampered", true}
                };
    }

    /**
     * Test if Bleichenbacher attack is possible.
     *
     * @param mode First two bytes of PKCS#1 message which defines the op-mode
     * @param separate Separate byte between padding and data in PKCS#1 message
     * @param version Protocol version
     * @param changeByteArray True if padding should be changed
     * @param position Position where padding is changed
     * @param description Test description
     * @param tamperMAC Destroy Finished MAC of RecordFrame
     */
    @Test(enabled = true, dataProvider = "bleichenbacher")
    public final void testBleichenbacherPossible(final byte[] mode,
            final byte[] separate, final EProtocolVersion version,
            final boolean changePadding, final SSLTestUtils.POSITIONS position,
            final String description, boolean tamperMAC) {
        this.pkcsMode = mode.clone();
        this.separateByte = separate.clone();
        this.protocolVersionPMS = version;
        this.chgPadding = changePadding;
        this.positionOfPaddingChange = position;
        this.destroyMAC = tamperMAC;
        boolean canceled = false;

        System.out.println("Test description: " + description);
        logger.info("Test description: " + description);
        logger.info("Test repeated: " + NUMBER_OF_REPETIIONS + " times");
        logger.info("Time measurement: Time between CLIENT_KEY_EXCHANGE and "
                + "SERVER_CHANGE_CIPHER_SPEC or ALERT");
        try {
            for (int i = 0; i < NUMBER_OF_REPETIIONS; i++) {
                workflow = new SSLHandshakeWorkflow(ACCURATE_TIMING);
                workflow.connectToTestServer(HOST, PORT);
                workflow.addObserver(this, EStates.CLIENT_HELLO);
                workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
                workflow.addObserver(this, EStates.CLIENT_FINISHED);
                workflow.start();

                delays[i] = analyzeTrace(workflow.getTraceList());
                workflow.closeSocket();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Long averagedTime = doStatistics(delays);
        logger.info("Averaged time (ns):");
        if (canceled) {
            logger.info("computation not possible");
        } else {
            logger.info(averagedTime.toString());
        }
        logger.info("------------------------------");
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public final void update(final Observable o, final Object arg) {
        EStates states = null;
        Trace trace = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
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
                    clientHello = builder.createClientHello(
                            EProtocolVersion.TLS_1_0.getId(), random.encode(
                            false),
                            suites.encode(false), new byte[]{0x00});

                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            protocolVersionRecord,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms = 
                            new PreMasterSecret(protocolVersionPMS);
                    workflow.setPreMasterSecret(pms);
                    pms.setProtocolVersion(this.protocolVersionPMS);
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
                    utils.setSeparateByte(this.separateByte);
                    utils.setMode(this.pkcsMode);
                    //generate the PKCS#1 padding string
                    byte[] padding = utils.createPaddingString(utils.
                            getPaddingLength());
                    if (this.chgPadding) {
                        padding = utils.changeByteArray(padding,
                                this.positionOfPaddingChange, (byte) 0x00);
                        utils.setPadding(padding);
                    }

                    //put the PKCS#1 pieces together
                    byte[] clear = utils.buildPKCS1Msg(encodedPMS);

                    //compute c = m^e mod n (RSA encryption)
                    byte[] ciphertext = null;
                    try {
                        ciphertext = RSACore.rsa(clear, rsaPK);
                        encPMS.setEncryptedPreMasterSecret(ciphertext);
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }

                    cke.setExchangeKeys(encPMS);

                    trace.setTimeMeasurementEnabled(true);
                    trace.setCurrentRecord(cke);
                    break;
                case CLIENT_FINISHED:
                    if (destroyMAC) {
                        ARecordFrame finished = trace.getCurrentRecord();
                        byte[] payload = finished.encode(true);
                        // frag the mac
//                        payload[24] = 1;
                        trace.setCurrentRecordBytes(payload);
                    }
                    break;
                default:
                    break;
            }
        }

    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public final void tearDown() {
        try {
            if (sslServer != null) {
                sslServer.shutdown();
                sslServer = null;
            }

            if (sslServerThread != null) {
                sslServerThread.interrupt();
                sslServerThread = null;
            }

            Thread.interrupted();
            sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public final void setUp() {
        try {
//            System.setProperty("javax.net.debug", "ssl");
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Analyzes a given Trace list and computes timing delay.
     *
     * @param traces Trace list
     * @return Timing delay.
     */
    private static long analyzeTrace(final List<Trace> traces) {
        Long delay = 0L;
        Long timestamp = 0L;
        Long overall = -1L;

        for (Trace trace : traces) {
            if (trace.getState() != null) {
                if (ACCURATE_TIMING) {
                    timestamp = trace.getAccurateTime();
                } else {
                    timestamp = trace.getNanoTime();
                }

                switch (trace.getState()) {
                    case CLIENT_KEY_EXCHANGE:
                        delay = timestamp;
                        break;
                    case SERVER_CHANGE_CIPHER_SPEC:
                        overall = timestamp - delay;
                        break;
                    case ALERT:
                        overall = timestamp - delay;
                        break;
                    default:
                        break;
                }
            }
        }
        return overall;
    }

    /**
     * Computes the arithmetic mean on a set of delay values.
     *
     * @param delayValues Delays
     * @return Arithmetic mean of given delays.
     */
    private static long doStatistics(final long[] delayValues) {
        long overall = 0L;
        for (long delay : delayValues) {
            overall += delay;
        }
        overall /= delayValues.length;

        return overall;
    }

    /**
     * Initialize logging properties
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
    }
}
