package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.ClientKeyExchangeParameters;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.net.SocketException;

public class FingerprintClientKeyExchange implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Test port.
     */
    private static final int PORT = 9443;
    /**
     * Test parameters.
     */
    private ClientKeyExchangeParameters parameters = new ClientKeyExchangeParameters();
    /**
     * Log4j logger initialization.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Default protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;

    /**
     * Load the logging properties.
     */
    @BeforeClass
    public void setUp() {
        PropertyConfigurator.configure("logging.properties");
    }

    /**
     * Test parameters for ClientKeyExchange fingerprinting.
     *
     * @return List of parameters
     */
    @DataProvider(name = "clientKeyExchange")
    public Object[][] createData1() {
        return new Object[][]{
                    {"Invalid payload for RSA key exchange", new ECipherSuite[]{
                            ECipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
                        new byte[]{(byte) 0x00, (byte) 0x00}}
                };
    }

    /**
     * Start SSL handshake.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    @Test(enabled = true, dataProvider = "clientKeyExchange")
    public void fingerprintClientKeyExchange(String desc,
            ECipherSuite[] cipherSuite, byte[] payload) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new SSLHandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
        parameters.setCipherSuite(cipherSuite);
        parameters.setPayload(payload);
        parameters.setTestClassName(this.getClass().getName());
        parameters.setDescription(desc);

        workflow.start();

        //analyze the handshake trace
        AFingerprintAnalyzer analyzer = new TestHashAnalyzer(parameters);
        analyzer.analyze(workflow.getTraceList());

        this.counter++;
        logger.info("++++Test finished.++++");
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(Observable o, Object arg) {
        MessageBuilder msgBuilder = new MessageBuilder();
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(parameters.getCipherSuite());
                    ClientHello clientHello = msgBuilder.createClientHello(EProtocolVersion.TLS_1_0.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    ClientKeyExchange cke = msgBuilder.createClientKeyExchange(
                            protocolVersion, this.workflow);
                    ClientDHPublic clientDHPublic = new ClientDHPublic();
                    clientDHPublic.setDhyc(parameters.getPayload());
                    cke.setExchangeKeys(clientDHPublic);
                    //update the trace object
                    trace.setCurrentRecord(cke);
                default:
                    break;
            }
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
    }
}
