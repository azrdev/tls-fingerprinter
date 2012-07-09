package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.HeaderParameters;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.net.SocketException;

/**
 * Fingerprint the Client Hello handshake header. Perform Tests by manipulating
 * the message type, protocol version and length bytes in the header.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 31, 2012
 */
public class FingerprintCHHandshakeHeader implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 9443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Defualt protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test parameters
     */
    private HeaderParameters parameters = new HeaderParameters();
    static Logger logger = Logger.getRootLogger();

    @BeforeClass
    public void setUp() {
        PropertyConfigurator.configure("logging.properties");
    }

    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "handshakeHeader", invocationCount = 1)
    public void manipulateCHHandshakeHeader(String desc, byte[] msgType,
            byte[] protocolVersion, byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        logger.info("Following test parameters are used:");
        workflow = new SSLHandshakeWorkflow();
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");

        parameters.setMsgType(msgType);
        parameters.setProtocolVersion(protocolVersion);
        parameters.setRecordLength(recordLength);
        parameters.setTestClassName(this.getClass().getName());
        parameters.setDescription(desc);

        workflow.start();

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
        if (states == EStates.CLIENT_HELLO) {
            ECipherSuite[] suites = new ECipherSuite[]{
                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
            CipherSuites cipherSuites = new CipherSuites();
            cipherSuites.setSuites(suites);
            RandomValue random = new RandomValue();
            byte[] compMethod = new byte[]{0x00};
            ClientHello clientHello = msgBuilder.createClientHello(this.protocolVersion.
                    getId(),
                    random.encode(false), cipherSuites.encode(false), compMethod);
            byte[] payload = clientHello.encode(true);
            if (parameters.getMsgType() != null) {
                byte[] msgType = parameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 5, msgType.length);
            }
            if (parameters.getRecordLength() != null) {
                byte[] recordLength = parameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 6,
                        recordLength.length);
            }
            if (parameters.getProtocolVersion() != null) {
                byte[] protVersion = parameters.getProtocolVersion();
                System.arraycopy(protVersion, 0, payload, 9, protVersion.length);
            }
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(clientHello);
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
