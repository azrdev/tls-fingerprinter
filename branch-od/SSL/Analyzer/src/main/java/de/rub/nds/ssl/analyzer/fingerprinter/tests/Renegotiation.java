package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
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
import java.util.ArrayList;
import java.util.Observable;
import java.util.Observer;

/**
 * Execute the handshake with valid headerParameters.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public final class Renegotiation extends AGenericFingerprintTest implements Observer {

    /**
     * Cipher suite.
     */
    private ECipherSuite[] suite;
    
    private ArrayList<ARecordFrame> msgBuffer;
    
    private int state = 0;

    private TestResult executeHandshake(final String desc,
            final ECipherSuite[] suite) throws SocketException {
        msgBuffer = new ArrayList<ARecordFrame>();
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow(true);
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());
        workflow.addObserver(this, EStates.ALERT);
        workflow.addObserver(this, EStates.APPLICATION);
        workflow.addObserver(this, EStates.APPLICATION_PING);
        this.suite = suite;
        

        //set the test headerParameters
        headerParameters.setIdentifier(EFingerprintTests.TLS_RENEGOTIATION);
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
        ARecordFrame record;
        MessageBuilder msgBuilder = workflow.getMessageBuilder();
        EStates states = null;
        ObservableBridge obs;
        if(o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
//            trace = (MessageContainer) arg;
        }
        if(states == EStates.ALERT){
            logger.debug("No renegotiation possible.");
            workflow.endApplicationPhase();
        }
       
        if(states == EStates.APPLICATION_PING){
            ArrayList<ARecordFrame> messages = workflow.getMessages();
            if (messages != null){
                workflow.endApplicationPhase();
            }
            switch(EStates.getStateById(state)){
                case SERVER_HELLO:
                case SERVER_CERTIFICATE:
                case SERVER_KEY_EXCHANGE:
                case SERVER_CERTIFICATE_REQUEST:
                case SERVER_HELLO_DONE:
                    //ArrayList<ARecordFrame> messages = workflow.getMessages();
                    if (messages != null){
                        //for(ARecordFrame msg: messages)
                    }
                    break;
                case CLIENT_CERTIFICATE:
                case CLIENT_KEY_EXCHANGE:
                case CLIENT_CERTIFICATE_VERIFY:
                case CLIENT_CHANGE_CIPHER_SPEC:
                case CLIENT_FINISHED:
                case SERVER_CHANGE_CIPHER_SPEC:
                case SERVER_FINISHED:

            }
        }
        
        if(states == EStates.APPLICATION){
            /*
            record = msgBuilder.createClientHello(protocolVersion);
            utils.setClientRandom((ClientHello) record);
            workflow.applicationSend(record);
            logger.debug("R - client hello sent");
            state++;*/
            
            String test = "test";
            record = msgBuilder.createApplication(protocolVersion, test.getBytes());
            workflow.applicationSend(record);
            
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