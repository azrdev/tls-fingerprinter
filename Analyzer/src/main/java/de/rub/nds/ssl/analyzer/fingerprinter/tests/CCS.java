package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.parameters.ChangeCipherSpecParams;
import de.rub.nds.ssl.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

public class CCS extends AGenericFingerprintTest implements Observer {

    /**
     * Test headerParameters.
     */
    private ChangeCipherSpecParams ccsParameters = new ChangeCipherSpecParams();

    /**
     * Fingerprint the CCS message.
     */
    private ResultWrapper fingerprintChangeCipherSpec(String desc,
            byte[] payload) throws SocketException, MalformedURLException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();

        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test headerParameters
        ccsParameters.setPayload(payload);
        ccsParameters.setIdentifier(EFingerprintIdentifier.ChangeCipherSpec);
        ccsParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(ccsParameters, workflow.getTraceList());
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(Observable o, Object arg) {
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_CHANGE_CIPHER_SPEC) {
            ChangeCipherSpec ccs = new ChangeCipherSpec(protocolVersion);
            byte[] payload = ccs.encode(true);
            byte[] tmp = null;
            if (ccsParameters.getPayload() != null) {
                byte[] testContent = ccsParameters.getPayload();
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
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Wrong payload", new byte[]{(byte) 0xff}},
            {"Invalid payload", new byte[]{0x02, 0x01}}
        };

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = fingerprintChangeCipherSpec((String) parameters[i][0],
                    (byte[]) parameters[i][1]);
        }

        return result;
    }
}
