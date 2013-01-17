package de.rub.nds.ssl.analyzer.tests.fingerprint;

import de.rub.nds.ssl.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.analyzer.tests.parameters.ChangeCipherSpecParams;
import de.rub.nds.ssl.analyzer.tests.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.util.Observable;
import java.util.Observer;

public class CCS extends GenericFingerprintTest implements Observer {

    /**
     * Test parameters.
     */
    private ChangeCipherSpecParams parameters = new ChangeCipherSpecParams();

    /**
     * Fingerprint the CCS message.
     */
    private void fingerprintChangeCipherSpec(String desc,
            byte[] payload) throws SocketException, MalformedURLException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        URL url = targetAsURL();
        workflow = new TLS10HandshakeWorkflow();
        
        //connect to test server
        workflow.connectToTestServer(url.getHost(), url.getDefaultPort());
        logger.info("Test Server: " + HOST + ":" + PORT);
        
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
        parameters.setPayload(payload);
        parameters.setIdentifier(EFingerprintIdentifier.ChangeCipherSpec);
        parameters.setDescription(desc);

        workflow.start();

        //analyze the handshake trace
//        AFingerprintAnalyzer analyzer = new TestHashAnalyzer(parameters);
//        analyzer.analyze(workflow.getTraceList());

        this.counter++;
        logger.info("++++Test finished.++++");

        // close the Socket after the test run
        workflow.closeSocket();
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

    @Override
    public Object call() throws Exception {
        Object result = null;

        //Test parameters for CCS fingerprinting.
        Object[][] parameters = new Object[][]{
            {"Wrong payload", new byte[]{(byte) 0xff}},
            {"Invalid payload", new byte[]{0x02, 0x01}}
        };

        for (Object[] tmpParams : parameters) {
            fingerprintChangeCipherSpec((String) tmpParams[0],
                    (byte[]) tmpParams[1]);
        }
        return result;
    }
}
