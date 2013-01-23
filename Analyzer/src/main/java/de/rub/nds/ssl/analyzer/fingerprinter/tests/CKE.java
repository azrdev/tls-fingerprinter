package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.parameters.ClientKeyExchangeParams;
import de.rub.nds.ssl.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

public class CKE extends AGenericFingerprintTest
        implements Observer {

    /**
     * Test headerParameters.
     */
    private ClientKeyExchangeParams ckeParameters = new ClientKeyExchangeParams();

    /**
     *
     * @param desc
     * @param cipherSuite
     * @param payload
     * @return
     * @throws SocketException
     */
    public ResultWrapper fingerprintClientKeyExchange(String desc,
            ECipherSuite[] cipherSuite, byte[] payload) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test headerParameters
        ckeParameters.setCipherSuite(cipherSuite);
        ckeParameters.setPayload(payload);
        ckeParameters.setIdentifier(EFingerprintIdentifier.ClientKeyExchange);
        ckeParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(ckeParameters, workflow.getTraceList(),
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
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(ckeParameters.getCipherSuite());
                    ClientHello clientHello = msgBuilder.
                            createClientHello(EProtocolVersion.TLS_1_0.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    ClientKeyExchange cke = msgBuilder.createClientKeyExchange(
                            protocolVersion, this.workflow);
                    ClientDHPublic clientDHPublic = new ClientDHPublic();
                    clientDHPublic.setDhyc(ckeParameters.getPayload());
                    cke.setExchangeKeys(clientDHPublic);
                    //update the trace object
                    trace.setCurrentRecord(cke);
                default:
                    break;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Invalid payload for RSA key exchange", new ECipherSuite[]{
                    ECipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
                new byte[]{(byte) 0x00, (byte) 0x00}}
        };

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = fingerprintClientKeyExchange((String) parameters[i][0],
                    (ECipherSuite[]) parameters[i][1], (byte[]) parameters[i][2]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
