package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.fingerprinter.HandshakeEnumCheck;
import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
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
     * Execute handshake.
     */
    @Test(enabled = true)
    public void executeHandshake() throws SocketException {
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());
        workflow.start();
        //analyze the handshake trace
        IFingerprinter analyzer = new HandshakeEnumCheck();
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
    public ResultWrapper[] call() throws Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
