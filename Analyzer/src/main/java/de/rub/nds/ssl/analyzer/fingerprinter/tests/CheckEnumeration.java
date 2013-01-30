package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import java.net.SocketException;

/**
 * Check if handshake messages were enumerated.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public final class CheckEnumeration extends AGenericFingerprintTest {

    private TestResult executeHandshake() throws SocketException {
        String desc = "Check Handshake Enum";

        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //set the test headerParameters
        headerParameters.setIdentifier(EFingerprintTests.HANDSHAKE_ENUM);
        headerParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new TestResult(headerParameters, workflow.getTraceList(),
                getAnalyzer());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TestResult[] call() throws Exception {
        // Print Test Banner
        printBanner();
        // execute test(s)
        TestResult result = executeHandshake();
        result.setTestName(this.getClass().getCanonicalName());
        return new TestResult[]{result};
    }
}
