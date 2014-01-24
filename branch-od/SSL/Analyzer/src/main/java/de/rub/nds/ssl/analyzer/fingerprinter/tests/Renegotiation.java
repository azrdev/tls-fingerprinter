package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHelloDone;
import de.rub.nds.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import de.rub.nds.ssl.stack.workflows.response.CertificateHandler;
import de.rub.nds.ssl.stack.workflows.response.IHandshakeStates;
import de.rub.nds.ssl.stack.workflows.response.ServerHelloHandler;
import de.rub.nds.ssl.stack.workflows.response.ServerKeyExchangeHandler;
import java.net.SocketException;
import java.security.DigestException;
import java.util.ArrayList;
import java.util.LinkedList;
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
    
    private LinkedList<AHandshakeRecord> records;
    

    private TestResult executeHandshake(final String desc,
            final ECipherSuite[] suite) throws SocketException {
        records = new LinkedList<AHandshakeRecord>();
        msgBuffer = new ArrayList<ARecordFrame>();
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow(true);
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());
        workflow.addObserver(this, EStates.ALERT);
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
            //trace = (MessageContainer) arg;
        }
        if(states == EStates.ALERT){
            logger.debug("No renegotiation possible.");
            workflow.endApplicationPhase();
        }
       
        if(states == EStates.APPLICATION_PING){
            switch(EStates.getStateById(state)){
                case CLIENT_HELLO:
                    workflow.getHashBuilder().reset();
                    record = msgBuilder.createClientHello(protocolVersion);
                    record.encode(true);
                    utils.setClientRandom((ClientHello) record);
                    workflow.applicationSendEncrypted(record, true);
                    logger.debug("R - Client hello sent");
                    state++;
                    break;
                case SERVER_HELLO:
                case SERVER_CERTIFICATE:
                case SERVER_KEY_EXCHANGE:
                case SERVER_CERTIFICATE_REQUEST:
                case SERVER_HELLO_DONE:
                    boolean shdreceived = false;
                    ArrayList<ARecordFrame> messages = workflow.getMessages();
                    if ((messages != null) && (messages.size() > 0)){
                        byte[] message = messages.get(0).getBytes();
                        if(message[0] == EContentType.ALERT.getId()){
                            state = EStates.ALERT.getID();
                            return;
                        }
                        HandshakeEnumeration hse = new HandshakeEnumeration(message, true, KeyExchangeParams.getInstance().getKeyExchangeAlgorithm());
                        IHandshakeStates hsstate = null;
                        for(AHandshakeRecord r : hse.getMessages()){
                            records.addLast(r);
                            if(r instanceof ServerHello){
                                hsstate = new ServerHelloHandler();
                                hsstate.handleResponse(r);
                            }else if(r instanceof Certificate){                           
                                hsstate = new CertificateHandler();
                                hsstate.handleResponse(r);
                            }else if(r instanceof ServerKeyExchange){
                                hsstate = new ServerKeyExchangeHandler();
                                hsstate.handleResponse(r);
                            }else if(r instanceof ServerHelloDone){
                                shdreceived = true;
                            }
                        }
                        if(shdreceived)
                            state += 5;
                    }
                    break;
                case CLIENT_CERTIFICATE:                    
                case CLIENT_KEY_EXCHANGE:
                case CLIENT_CERTIFICATE_VERIFY:
                    record = msgBuilder.createClientKeyExchange(protocolVersion, workflow);
                    record.encode(true);
                    workflow.applicationSendEncrypted(record, true);
                    logger.debug("R - Client Key Exchange sent");
                    state += 3;
                    break;
                case CLIENT_CHANGE_CIPHER_SPEC:
                    record = new ChangeCipherSpec(protocolVersion);
                    record.encode(true);
                    workflow.applicationSendEncrypted(record, false);
                    logger.debug("R - Client Change Chipher Spec sent");
                    workflow.resetMessageBuilder();
                    state++;
                    break;
                case CLIENT_FINISHED:
                    MasterSecret masterSec = msgBuilder.createMasterSecret(workflow);
                    try {
                        workflow.setHash(workflow.getHashBuilder().getHandshakeMsgsHashes());
                    } catch (DigestException e) {
                        e.printStackTrace();
                    }
                    record = msgBuilder.createFinished(protocolVersion, EConnectionEnd.CLIENT, workflow.getHash(), masterSec);
                    record.encode(true);
                    workflow.applicationSendEncrypted(record, true);
                    logger.debug("R - Finished message sent");
                    state++;
                    break;
                case SERVER_CHANGE_CIPHER_SPEC:
                case SERVER_FINISHED:
                    messages = workflow.getMessages();
                    if ((messages != null) && (messages.size() > 0)){
                        byte[] message = messages.get(0).getBytes();
                        if(message[0] == EContentType.HANDSHAKE.getId()){
                            String txt = "test";
                            workflow.applicationSendEncrypted(msgBuilder.createApplication(protocolVersion, txt.getBytes()), false);
                            logger.debug("Renegotiation possible.");
                            workflow.endApplicationPhase();
                        }
                    }
                    break;
                case ALERT:
                    logger.debug("Renegotiation not possible.");
                    workflow.endApplicationPhase();
                    break;
            }
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TestResult[] call() throws Exception {
        Object[][] parameters = new Object[][]{{"TLS Renegotiation Vulnerability",
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