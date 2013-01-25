package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * Fingerprint the Client Hello handshake header. 
 * Perform Tests by manipulating the message type, protocol version and length 
 * bytes in the header.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 31, 2012
 */
public final class CHHandshakeHeader extends AGenericFingerprintTest 
    implements Observer {

    private ResultWrapper manipulateCHHandshakeHeader(final String desc,
            final byte[] msgType, final byte[] recordLength) throws
            SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        logger.info("Following test parameters are used:");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");

        //set the test headerParameters
        headerParameters.setMsgType(msgType);
        headerParameters.setRecordLength(recordLength);
        headerParameters.setIdentifier(EFingerprintIdentifier.CHHandshakeHeader);
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
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_HELLO) {
            ECipherSuite[] suites = new ECipherSuite[]{
                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
            CipherSuites cipherSuites = new CipherSuites();
            cipherSuites.setSuites(suites);
            RandomValue random = new RandomValue();
            byte[] compMethod = new byte[]{0x00};
            ClientHello clientHello = msgBuilder.
                    createClientHello(this.protocolVersion.
                    getId(),
                    random.encode(false), cipherSuites.encode(false), compMethod);
            byte[] payload = clientHello.encode(true);
            if (headerParameters.getMsgType() != null) {
                byte[] msgType = headerParameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 5, msgType.length);
            }
            if (headerParameters.getRecordLength() != null) {
                byte[] recordLength = headerParameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 6,
                        recordLength.length);
            }
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(clientHello);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Wrong message type", new byte[]{(byte) 0xff}, null},
            {"Invalid length 0x00,0x00,0x00", null,
                new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}},
            {"Invalid length 0xff,0xff,0xff", null,
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff}}};

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = manipulateCHHandshakeHeader((String) parameters[i][0],
                    (byte[]) parameters[i][1], (byte[]) parameters[i][2]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
