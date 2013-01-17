package de.rub.nds.ssl.analyzer.tests.fingerprint;

import de.rub.nds.ssl.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.analyzer.HandshakeEnumCheck;
import de.rub.nds.ssl.analyzer.removeMe.TestConfiguration;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import java.net.SocketException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

/**
 * Check if handshake messages were enumerated.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public class CheckEnumeration extends GenericFingerprintTest {
    /**
     * Test port.
     */
    protected int PORT = 9443;
    
    /**
     * Execute handshake.
     */
    @Test(enabled = true)
    public void executeHandshake() throws SocketException {
        workflow = new TLS10HandshakeWorkflow();
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
        workflow.start();
        //analyze the handshake trace
        AFingerprintAnalyzer analyzer = new HandshakeEnumCheck();
        analyzer.analyze(workflow.getTraceList());
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
    }

    @Override
    public Object call() throws Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
