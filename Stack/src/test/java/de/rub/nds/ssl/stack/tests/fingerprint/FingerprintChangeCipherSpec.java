package de.rub.nds.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.ChangeCipherSpecParams;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.tests.trace.Trace;
import de.rub.nds.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;

public class FingerprintChangeCipherSpec extends GenericFingerprintTest implements Observer {

    /**
     * Test parameters.
     */
	private ChangeCipherSpecParams parameters = new ChangeCipherSpecParams();

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
