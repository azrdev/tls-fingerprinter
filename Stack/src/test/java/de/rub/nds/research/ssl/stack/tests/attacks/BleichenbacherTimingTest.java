package de.rub.nds.research.ssl.stack.tests.attacks;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.common.SSLServer;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import sun.security.rsa.RSACore;

/**
 * Test for Bleichenbacher attack.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 12, 2012
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
     * TLS protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
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
    private byte[] separate;
    /**
     * Protocol version.
     */
    private EProtocolVersion version;
    /**
     * First two bytes of PKCS#1 message which defines the op-mode.
     */
    private byte[] mode;
    /**
     * Signalizes if padding should be changed.
     */
    private boolean changePadding;
    /**
     * Position in padding to change.
     */
    private int position;
    /**
     * First position in padding string.
     */
    public static final int FIRST_POSITION = 0;
    /**
     * Mid-position of the padding string.
     */
    public static final int MID_POSITION = 1;
    /**
     * Last position of the padding string.
     */
    public static final int LAST_POSITION = 2;
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
     * Overall delays
     */
    private final long[] delays = new long[NUMBER_OF_REPETIIONS];
    /**
     * Number of repetitions
     */
    private static final int NUMBER_OF_REPETIIONS = 1000;

    /**
     * Test parameters for the Bleichenbacher Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "bleichenbacher")
    public Object[][] createData1() {
        return new Object[][]{
                    // ok case
                    {new byte[]{0x00, 0x02}, new byte[]{0x00}, protocolVersion,
                        false, 0, "OK"},
                    // wrong protocol version in PreMasterSecret
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false, 0,
                        "Wrong protocol version in PreMasterSecret"},
//                    // seperate byte is not 0x00
//                    {new byte[]{0x00, 0x02}, new byte[]{0x01}, protocolVersion,
//                        false, 0, "Seperate byte is not 0x00"},
//                    // mode changed
//                    {new byte[]{0x00, 0x01}, new byte[]{0x00}, protocolVersion,
//                        false, 0, "Mode changed to 0x01"},
//                    // zero byte at the first position of the padding
//                    {new byte[]{0x00, 0x02}, new byte[]{0x00}, protocolVersion,
//                        true, 0,
//                        "Zero byte at the first position of the padding"},
//                    // zero byte in the middle of the padding string
//                    {new byte[]{0x00, 0x02}, new byte[]{0x00}, protocolVersion,
//                        true, 1,
//                        "Zero byte in the middle of the padding string"},
//                    // zero byte at the end of the padding string
//                    {new byte[]{0x00, 0x02}, new byte[]{0x00}, protocolVersion,
//                        true, 2, "Zero byte at the end of the padding string"}
                };
    }

    /**
     * Test if Bleichenbacher attack is possible.
     *
     * @param mode First two bytes of PKCS#1 message which defines the op-mode
     * @param separate Separate byte between padding and data in PKCS#1 message
     * @param version Protocol version
     * @param changePadding True if padding should be changed
     * @param position Position where padding is changed
     * @param description Test description
     */
    @Test(enabled = true, dataProvider = "bleichenbacher")
    public final void testBleichenbacherPossible(final byte[] mode,
            final byte[] separate, final EProtocolVersion version,
            final boolean changePadding, final int position,
            final String description) {
        this.mode = mode;
        this.separate = separate;
        this.version = version;
        this.changePadding = changePadding;
        this.position = position;
        boolean canceled = false;

        System.out.printf("\n%-25s%-50s\n", "Test description:", description);
        System.out.printf("%-25s%-50s\n", "Test repeated:",
                NUMBER_OF_REPETIIONS + " times");
        System.out.printf("%-25s%-50s\n", "Time measurement:",
                "Time between CLIENT_KEY_EXCHANGE and SERVER_CHANGE_CIPHER_SPEC");
        try {
            for (int i = 0; i < NUMBER_OF_REPETIIONS; i++) {
                workflow = new SSLHandshakeWorkflow();
                workflow.connectToTestServer(HOST, PORT);
                workflow.addObserver(this, EStates.CLIENT_HELLO);
                workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
                workflow.addObserver(this, EStates.CLIENT_FINISHED);
                workflow.start();

                ArrayList<Trace> traceList = workflow.getTraceList();
                ARecordFrame frame = traceList.get(traceList.size() - 1).
                        getCurrentRecord();
                if (frame instanceof Alert) {
                    Alert alert = (Alert) frame;
//                    if (EAlertLevel.FATAL.equals(alert.getAlertLevel())) {
//                        canceled = true;
//                        System.out.printf("%-25s%-50s\n", "Test aborted:",
//                                alert.getAlertLevel() 
//                                + " " 
//                                + alert.getAlertDescription());
//                        break;
//                    } else {
//                        continue;
//                    }

//                    Assert.fail("Test failed with an SSL-Alert: "
//                            + alert.getAlertLevel() + " "
//                            + alert.getAlertDescription());
                }
                if ((frame instanceof TLSCiphertext) == false) {
//                Assert.fail("Last message not Encrypted finished message");
                }

                delays[i] = analyzeTrace(workflow.getTraceList());
//            System.out.printf("%10d ns\n",delays[i]);
                workflow.getSocket().close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Long averagedTime = doStatistics(delays);
        System.out.printf("%-25s", "Averaged time (ns):");
        if (canceled) {
            System.out.printf("%-50s\n", "computation not possible");
        } else {
            System.out.printf("%-50s\n", averagedTime);
        }

    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        EStates states = null;
        Trace trace = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        switch (states) {
            case CLIENT_HELLO:
                MessageBuilder builder = new MessageBuilder();
                CipherSuites suites = new CipherSuites();
                RandomValue random = new RandomValue();
                suites.setSuites(new ECipherSuite[]{
                            ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                clientHello = builder.createClientHello(EProtocolVersion.TLS_1_0.
                        getId(),
                        random.encode(false),
                        suites.encode(false), new byte[]{0x00});

                trace.setCurrentRecord(clientHello);
                break;
            case CLIENT_KEY_EXCHANGE:
                KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
                PublicKey pk = keyParams.getPublicKey();
                ClientKeyExchange cke = new ClientKeyExchange(protocolVersion,
                        keyParams.getKeyExchangeAlgorithm());
                PreMasterSecret pms = new PreMasterSecret(protocolVersion);
                workflow.setPreMasterSecret(pms);
                pms.setProtocolVersion(this.version);
                byte[] encodedPMS = pms.encode(false);

                //encrypt the PreMasterSecret
                EncryptedPreMasterSecret encPMS = new EncryptedPreMasterSecret(
                        pk);
                BigInteger mod = null;
                RSAPublicKey rsaPK = null;
                if (pk instanceof RSAPublicKey) {
                    rsaPK = (RSAPublicKey) pk;
                    mod = rsaPK.getModulus();
                }
                int modLength = mod.bitLength() / 8;

                /*
                 * set the padding length of the PKCS#1 padding string (it is
                 * [<Modulus length> - <Data length> -3])
                 */
                utils.setPaddingLength((modLength - encodedPMS.length - 3));
                utils.setSeperateByte(this.separate);
                utils.setMode(this.mode);
                //generate the PKCS#1 padding string
                byte[] padding = utils.createPaddingString(utils.
                        getPaddingLength());
                if (this.changePadding) {
//                    Assert.assertFalse(this.position > utils.getPaddingLength(),
//                            "Position to large - padding length is "
//                            + utils.getPaddingLength());
                    utils.changePadding(padding, this.position);
                }
                //put the PKCS#1 pieces together
                byte[] clear = utils.buildPKCS1Msg(encodedPMS);

                //compute c = m^e mod n (RSA encryption)
                byte[] ciphertext = null;
                try {
                    ciphertext = RSACore.rsa(clear, rsaPK);
                } catch (BadPaddingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                encPMS.setEncryptedPreMasterSecret(ciphertext);
                cke.setExchangeKeys(encPMS);

                trace.setCurrentRecord(cke);
                break;
                
            case CLIENT_FINISHED:
//                ARecordFrame frame = trace.getCurrentRecord();
//                byte[] tmp = frame.encode(true);
//                tmp[tmp.length-35] = 0x1;
//                frame.decode(tmp, true);
//                trace.setCurrentRecord(frame);
            default:
                break;
        }

    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        try {
//            System.out.println("sslServer shutdown: " + sslServer);
            sslServer.shutdown();
            sslServer = null;
            sslServerThread.interrupt();
            sslServerThread = null;

            Thread.currentThread().sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
        try {
//            System.setProperty("javax.net.debug", "ssl");
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
//            System.out.println("sslServer startup: " + sslServer);
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static final long analyzeTrace(final List<Trace> traces) {
        Long delay = 0L;
        Long timestamp = 0L;
        Long overall = -1L;
//        System.out.printf("%50s", "===> Test duration <===\n");

        for (Trace trace : traces) {
            if (trace.getState() != null) {
//                System.out.printf("%40s", trace.getState().name() + "\n");
                timestamp = trace.getNanoTime();
                EStates currentState = trace.getState();
                switch (trace.getState()) {
                    case CLIENT_KEY_EXCHANGE:
                        delay = timestamp;
                        break;
                    case SERVER_CHANGE_CIPHER_SPEC:
                        overall = timestamp - delay;
                        break;
                    case ALERT:
                        overall = timestamp - delay;
//                        if (trace.getCurrentRecord() instanceof Alert) {
//                            System.out.println("Alert reason: " 
//                                    + ((Alert) trace.getCurrentRecord()).
//                                    getAlertDescription());
//                        }
                        break;
                }
            }
//            System.out.println(": " + timestamp + "ns");
        }
        return overall;
    }

    private static final long doStatistics(long[] delayValues) {
        long overall = 0L;
        for (long delay : delayValues) {
            overall += delay;
        }
        overall /= delayValues.length;

        return overall;
    }
}
