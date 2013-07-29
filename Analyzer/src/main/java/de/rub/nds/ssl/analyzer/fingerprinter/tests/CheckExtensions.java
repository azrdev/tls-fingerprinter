package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.analyzer.parameters.ClientHelloParameters;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * This check determines the supported extensions of the counterpart.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Feb 4, 2013
 */
public class CheckExtensions extends AGenericFingerprintTest implements Observer {

    private ClientHelloParameters chParameters = new ClientHelloParameters();

    private TestResult manipulateCHExtensionsList(final String desc,
            final byte[] extensions) throws
            SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, TLS10HandshakeWorkflow.EStates.CLIENT_HELLO);
        logger.info(TLS10HandshakeWorkflow.EStates.CLIENT_HELLO.name()
                + " state is observed");

        //set the test clientParameters
//        chParameters.setIdentifier(EFingerprintTests.EXTENSIONS);
        chParameters.setDescription(desc);
        chParameters.setExtensions(extensions);

        try {
            workflow.start();

            this.counter++;
            for (MessageContainer msg : workflow.getTraceList()) {
                if (msg.getState()
                        == TLS10HandshakeWorkflow.EStates.SERVER_HELLO) {
                    ServerHello serverHelloMsg =
                            (ServerHello) msg.getCurrentRecord();

                    Extensions serverExtensions =
                            serverHelloMsg.getExtensions();
                    if (serverExtensions != null) {
                        logger.info("Supported extensions: \n");
                        for (EExtensionType ex : serverExtensions.getExtensions()) {
                            logger.info(ex.name() + "\n");
                        }
                    }

                    break;
                }
            }
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new TestResult(chParameters, workflow.getTraceList(),
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
        TLS10HandshakeWorkflow.EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == TLS10HandshakeWorkflow.EStates.CLIENT_HELLO) {
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
            Extensions extensions = new Extensions(chParameters.getExtensions());
            clientHello.setExtensions(extensions);
            byte[] payload = clientHello.encode(true);

            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(clientHello);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TestResult[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Add all extensions", new Extensions().encode(false)}
        };

        // Print Test Banner
        printBanner();
        // execute test(s)
        TestResult[] result = new TestResult[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = manipulateCHExtensionsList((String) parameters[i][0],
                    (byte[]) parameters[i][1]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
