package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ApplicationRecord;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.io.IOException;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * Execute the handshake with valid headerParameters.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public final class GoodCase extends AGenericFingerprintTest implements Observer {

    /**
     * Cipher suite.
     */
    private ECipherSuite[] suite;
    private int blub = 0;

    private TestResult executeHandshake(final String desc,
            final ECipherSuite[] suite) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow(true);
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.APPLICATION);
        workflow.addObserver(this, EStates.APPLICATION_PING);
        this.suite = suite;
        

        //set the test headerParameters
        headerParameters.setIdentifier(EFingerprintTests.GOOD);
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
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_HELLO) {
            MessageBuilder builder = new MessageBuilder();
            CipherSuites suites = new CipherSuites();
            RandomValue random = new RandomValue();
            suites.setSuites(this.suite);
            ClientHello clientHello = builder.createClientHello(protocolVersion.
                    getId(),
                    random.encode(false),
                    suites.encode(false), new byte[]{0x00});
            trace.setCurrentRecord(clientHello);
        }
       
        if(states == EStates.APPLICATION){
            logger.debug("Schön hier in der Application phase.");
            /*
            MessageBuilder builder = new MessageBuilder();
            CipherSuites suites = new CipherSuites();
            RandomValue random = new RandomValue();
            suites.setSuites(this.suite);
            ClientHello clientHello = builder.createClientHello(protocolVersion.
                    getId(),
                    random.encode(false),
                    suites.encode(false), new byte[]{0x00});
            trace = new MessageContainer();
            trace.setCurrentRecord(clientHello);
            trace.prepare();
            try{
                workflow.send(trace);
            }catch(IOException e){
            }*/
        }
        if(states == EStates.APPLICATION_PING){
            if(workflow.getMessages() != null){
                logger.debug("Da is wat!");
                workflow.applicationSend(new byte[]{13, 37});
                workflow.endApplicationPhase();
            }
                
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TestResult[] call() throws Exception {
        Object[][] parameters = new Object[][]{{"Good case",
                new ECipherSuite[]{ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA}}
        };

        // Print Test Banner
        printBanner();
        // execute test(s)
        TestResult[] result = new TestResult[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = executeHandshake((String) parameters[i][0],
                    (ECipherSuite[]) parameters[i][1]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
