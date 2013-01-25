package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * Fingerprint the ClientKeyExchange record header. Perform Tests by
 * manipulating the message type, protocol version and length bytes in the
 * record header.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 04, 2012
 */
public final class CKERecordHeader extends AGenericFingerprintTest implements
        Observer {

    private ResultWrapper manipulateCKERecordHeader(final String desc,
            final byte[] msgType, final byte[] protocolVersion,
            final byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");

        //set the test headerParameters
        headerParameters.setMsgType(msgType);
        headerParameters.setProtocolVersion(protocolVersion);
        headerParameters.setRecordLength(recordLength);
        headerParameters.setIdentifier(EFingerprintTests.CKE_RH);
        headerParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(headerParameters, workflow.getTraceList(),
                getAnalyzer());
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
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_KEY_EXCHANGE) {
            ClientKeyExchange cke = msgBuilder.createClientKeyExchange(
                    protocolVersion, workflow);
            byte[] payload = cke.encode(true);
            //change msgType of the message
            if (headerParameters.getMsgType() != null) {
                byte[] msgType = headerParameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 0, msgType.length);
            }
            //change record length of the message
            if (headerParameters.getRecordLength() != null) {
                byte[] recordLength = headerParameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 3,
                        recordLength.length);
            }
            //change protocol version of the message
            if (headerParameters.getProtocolVersion() != null) {
                byte[] protVersion = headerParameters.getProtocolVersion();
                System.arraycopy(protVersion, 0, payload, 1, protVersion.length);
            }
            //update the trace object
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(cke);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Wrong message type", new byte[]{(byte) 0xff}, null, null},
            {"Invalid protocol version 0xff,0xff", null,
                new byte[]{(byte) 0xff, (byte) 0xff}, null},
            {"Invalid length 0x00,0x00", null, null,
                new byte[]{(byte) 0x00, (byte) 0x00}},
            {"Invalid length 0xff,0xff", null, null,
                new byte[]{(byte) 0xff, (byte) 0xff}}};

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = manipulateCKERecordHeader((String) parameters[i][0],
                    (byte[]) parameters[i][1], (byte[]) parameters[i][2],
                    (byte[]) parameters[i][3]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
