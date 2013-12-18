package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.analyzer.parameters.HandshakeParams;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import java.net.SocketException;
import java.util.ArrayList;

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
        workflow = new TLS10HandshakeWorkflow(false);
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //set the test headerParameters
        HandshakeParams handshakeParams = new HandshakeParams();
//        handshakeParams.setIdentifier(EFingerprintTests.GOOD);
        handshakeParams.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            boolean isContinued = testForHandshakeEnumeration(workflow.
                getTraceList());
            handshakeParams.setContinued(isContinued);
            logger.info("Handshake message stapling enabled: " + isContinued);
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new TestResult(handshakeParams, workflow.getTraceList(),
                getAnalyzer());
    }

    /**
     * Tests if the remote side relies on handshake enumeration.
     *
     * @param traceList Complete workflow trace of a successful run.
     * @return true if the communication partner relies on handshake
     * enumeration.
     */
    private boolean testForHandshakeEnumeration(
            final ArrayList<MessageContainer> traceList) {
        boolean result = false;
        MessageContainer currentTrace;
        for (int i = 0; i < traceList.size(); i++) {
            currentTrace = traceList.get(i);
            if (currentTrace.getState()
                    == TLS10HandshakeWorkflow.EStates.SERVER_HELLO
                    && currentTrace.isContinued()) {
                result = true;
                break;
            }
        }
        return result;
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
