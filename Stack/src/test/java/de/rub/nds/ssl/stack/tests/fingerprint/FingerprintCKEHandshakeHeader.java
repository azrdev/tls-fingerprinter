package de.rub.nds.ssl.stack.tests.fingerprint;

import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.trace.Message;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;

public class FingerprintCKEHandshakeHeader extends GenericFingerprintTest implements Observer {

    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "handshakeHeader", invocationCount = 1)
    public void manipulateCKERecordHeader(String desc, byte[] msgType,
            byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
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
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");

        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setRecordLength(recordLength);
        parameters.setIdentifier(EFingerprintIdentifier.CKEHandshakeHeader);
        parameters.setDescription(desc);

        //start the handshake
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
    public void update(final Observable o, final Object arg) {
        MessageBuilder msgBuilder = new MessageBuilder();
        Message trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Message) arg;
        }
        if (states == EStates.CLIENT_KEY_EXCHANGE) {
            ClientKeyExchange cke = msgBuilder.createClientKeyExchange(
                    protocolVersion, workflow);
            byte[] payload = cke.encode(true);
            //change msgType of the message
            if (parameters.getMsgType() != null) {
                byte[] msgType = parameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 5, msgType.length);
            }
            if (parameters.getRecordLength() != null) {
                byte[] recordLength = parameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 6,
                        recordLength.length);
            }
            //update the trace object
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(cke);
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
