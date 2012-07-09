package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.ChangeCipherSpecParameters;
import de.rub.nds.research.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.net.SocketException;

public class FingerprintChangeCipherSpec implements Observer {

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
    private static final int PORT = 443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Default protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test parameters.
     */
    private ChangeCipherSpecParameters parameters = new ChangeCipherSpecParameters();
    /**
     * Log4j logger initialization.
     */
    static Logger logger = Logger.getRootLogger();

    /**
     * Load the logging properties.
     */
    @BeforeClass
    public void setUp() {
        PropertyConfigurator.configure("logging.properties");
    }

    /**
     * Test parameters for ChangeCipherSpec fingerprinting.
     *
     * @return List of parameters
     */
    @DataProvider(name = "changeCipherSpec")
    public Object[][] createData1() {
        return new Object[][]{
                    {"Wrong payload", new byte[]{(byte) 0xff}},
                    {"Invalid payload", new byte[]{0x02, 0x01}}
                };
    }

    /**
     * Fingerprint the ChangeCipherSpec message.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    @Test(enabled = true, dataProvider = "changeCipherSpec")
    public void fingerprintChangeCipherSpec(String desc,
            byte[] payload) throws SocketException {
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
        workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
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
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states == EStates.CLIENT_CHANGE_CIPHER_SPEC) {
            ChangeCipherSpec ccs = new ChangeCipherSpec(protocolVersion);
            byte[] payload = ccs.encode(true);
            byte[] tmp = null;
            if (parameters.getPayload() != null) {
                byte[] testContent = parameters.getPayload();
                tmp = new byte[payload.length + testContent.length - 1];
                //copy header
                System.arraycopy(payload, 0, tmp, 0, payload.length - 1);
                //copy test parameter
                System.arraycopy(testContent, 0, tmp, payload.length - 1,
                        testContent.length);
            }
            //update the trace object
            trace.setCurrentRecordBytes(tmp);
            trace.setCurrentRecord(ccs);
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
