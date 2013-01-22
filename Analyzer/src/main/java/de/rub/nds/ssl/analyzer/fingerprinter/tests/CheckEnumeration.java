package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import java.net.SocketException;

/**
 * Check if handshake messages were enumerated.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public class CheckEnumeration extends AGenericFingerprintTest {

    /**
     *
     * @return @throws SocketException
     */
    public ResultWrapper executeHandshake() throws SocketException {
        String desc = "Check Handshake Enum";
        
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //set the test headerParameters
        headerParameters.setIdentifier(EFingerprintIdentifier.CheckHandEnum);
        headerParameters.setDescription(desc);
        
        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        //analyze the handshake trace
//        IFingerprinter analyzer = new HandshakeEnumCheck();
//        analyzer.analyze(workflow.getTraceList());
        return new ResultWrapper(headerParameters, workflow.getTraceList());
    }

    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        // Print Test Banner
        printBanner();
        // execute test(s)
        return new ResultWrapper[]{executeHandshake()};
    }
}