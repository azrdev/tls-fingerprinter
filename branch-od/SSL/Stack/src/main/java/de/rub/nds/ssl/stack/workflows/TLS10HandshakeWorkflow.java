package de.rub.nds.ssl.stack.workflows;

import de.rub.nds.research.timingsocket.TimingSocket;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import de.rub.nds.ssl.stack.workflows.commons.HandshakeHashBuilder;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
import de.rub.nds.ssl.stack.workflows.commons.WorkflowState;
import de.rub.nds.ssl.stack.workflows.response.TLSResponse;
import de.rub.nds.ssl.stack.workflows.response.fecther.AResponseFetcher;
import de.rub.nds.ssl.stack.workflows.response.fecther.StandardFetcher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import static java.lang.Thread.sleep;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import org.apache.log4j.Logger;

/**
 * The complete TLS 1.0 Handshake workflow.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 * 
 * Feb 05, 2014
 */
public final class TLS10HandshakeWorkflow extends AWorkflow {

    // TODO add JavaDoc
    private final EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    private Socket so = null;
    private InputStream in = null;
    private OutputStream out = null;
    private MessageUtils utils = new MessageUtils();
    private PreMasterSecret pms = null;
    private byte[] handshakeHashes = null;
    private boolean encrypted = false;
    private boolean vnlEnabled = false;
    private final static Logger logger = Logger.getRootLogger();
    private HandshakeHashBuilder hashBuilder = null;
    private AResponseFetcher fetcher = null;
    private boolean enterApplicationPhase = false;
    private boolean runApplicationPhase = false;
    private ArrayList<ARecordFrame> responses = null;
    private MessageBuilder msgBuilder = null;

    /**
     * Define the workflow states.
     */
    public enum EStates implements WorkflowState {

    // TODO add JavaDoc
        CLIENT_HELLO,
        SERVER_HELLO,
        SERVER_CERTIFICATE,
        SERVER_KEY_EXCHANGE,
        SERVER_CERTIFICATE_REQUEST,
        SERVER_HELLO_DONE,
        CLIENT_CERTIFICATE,
        CLIENT_KEY_EXCHANGE,
        CLIENT_CERTIFICATE_VERIFY,
        CLIENT_CHANGE_CIPHER_SPEC,
        CLIENT_FINISHED,
        SERVER_CHANGE_CIPHER_SPEC,
        SERVER_FINISHED,
        ALERT,
        APPLICATION,
        APPLICATION_PING;

        @Override
        public int getID() {
            return this.ordinal();
        }

    // TODO add JavaDoc
        public static EStates getStateById(int id) {
            EStates[] states = EStates.values();
            return states[id];
        }
    }

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param workflowStates The SSL handshake states
     * @param socketType Socket type to be used
     */
    public TLS10HandshakeWorkflow(final WorkflowState[] workflowStates,
            final ESupportedSockets socketType, boolean enterApplicationPhase) throws SocketException {
        super(workflowStates);
        
        this.enterApplicationPhase = enterApplicationPhase;
        responses = new ArrayList<ARecordFrame>();
        
        switch (socketType) {
            case StandardSocket:
                so = new Socket();
                fetcher = new StandardFetcher(so, this);
                break;
//            case TimingSocket:
//                so = new TimingSocket();
//                fetcher = new TimingFetcher(so, this);
//                break;
            default: break;
        }
    }

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param socketType Socket type to be used
     * @throws SocketException  
     */
    public TLS10HandshakeWorkflow(final ESupportedSockets socketType, boolean enterApplicationPhase) throws
            SocketException {
        this(EStates.values(), socketType, enterApplicationPhase);
    }

    /**
     * Initialize the handshake workflow with the state values
     * @throws SocketException 
     */
    public TLS10HandshakeWorkflow(boolean enterApplicationPhase) throws SocketException {
        this(EStates.values(), ESupportedSockets.StandardSocket, enterApplicationPhase);
    }

    /**
     * Executes the complete SSL handshake.
     */
    @Override
    public void start() {
        msgBuilder = new MessageBuilder();
        try {
            logger.debug(">>> Start TLS handshake");
            setMainThread(Thread.currentThread());
            Thread respThread = new Thread(fetcher, "ResponseThread");
            setResponseThread(respThread);
            respThread.start();
            ARecordFrame record;
            MessageContainer trace;
            try {
                hashBuilder = new HandshakeHashBuilder();
            } catch (NoSuchAlgorithmException ex) {
                // TODO remove
                ex.printStackTrace();
            }

            /*
             * create the ClientHello
             */
            trace = new MessageContainer();
            record = msgBuilder.createClientHello(protocolVersion);
            setRecordTrace(trace, record);
            // switch the state of the handshake
            previousStateAndNotify(trace);
            // set the probably changed message
            record = trace.getCurrentRecord();
            // save the client random value for later computations
            utils.setClientRandom((ClientHello) record);
            // encode the message
            trace.prepare();
            // drop it on the wire!
            send(trace);
            logger.debug("Client Hello message sent");
            // hash current record
            updateHash(hashBuilder, trace);
            // add trace to ArrayList
            addToTraceList(new MessageContainer(EStates.CLIENT_HELLO, trace.
                    getCurrentRecord(),
                    trace.getOldRecord(), false));
            sleepPoller(EStates.SERVER_HELLO_DONE);

            /*
             * create ClientKeyExchange
             */
            trace = new MessageContainer();
            trace.setPreviousState(EStates.getStateById(
                    this.getCurrentState()));
            record = msgBuilder.createClientKeyExchange(protocolVersion, this);
            setRecordTrace(trace, record);
            // change status and notify observers
            switchToState(trace, EStates.CLIENT_KEY_EXCHANGE);
            // encode the message
            trace.prepare();
            // drop it on the wire!
            send(trace);
            logger.debug("Client Key Exchange message sent");

            // add trace to ArrayList
            addToTraceList(new MessageContainer(EStates.CLIENT_KEY_EXCHANGE,
                    trace.getCurrentRecord(),
                    trace.getOldRecord(), false));
            // hash current record
            updateHash(hashBuilder, trace);

            /*
             * create ChangeCipherSepc
             */
            trace = new MessageContainer();
            trace.setPreviousState(EStates.getStateById(
                    this.getCurrentState()));
            record = new ChangeCipherSpec(protocolVersion);
            setRecordTrace(trace, record);
            //change status and notify observers
            switchToState(trace, EStates.CLIENT_CHANGE_CIPHER_SPEC);
            // encode the message
            trace.prepare();
            // drop it on the wire!
            send(trace);

            logger.debug("Change Cipher Spec message sent");

            // switch to encrypted mode
            encrypted = true;
            // add trace to ArrayList
            addToTraceList(new MessageContainer(
                    EStates.CLIENT_CHANGE_CIPHER_SPEC,
                    trace.getCurrentRecord(),
                    trace.getOldRecord(), false));
            /*
             * create Finished
             */
            trace = new MessageContainer();
            trace.setPreviousState(EStates.getStateById(
                    this.getCurrentState()));
            // create the master secret
            MasterSecret masterSec = msgBuilder.createMasterSecret(this);
            // hash handshake messages
            try {
                handshakeHashes = hashBuilder.getHandshakeMsgsHashes();
            } catch (DigestException e) {
                // TODO remove
                e.printStackTrace();
            }
            record = msgBuilder.createFinished(protocolVersion,
                    EConnectionEnd.CLIENT, handshakeHashes, masterSec);
            record = msgBuilder.encryptRecord(protocolVersion, record, EContentType.HANDSHAKE);
            setRecordTrace(trace, record);
            // change status and notify observers
            switchToState(trace, EStates.CLIENT_FINISHED);
            // encode the message
            trace.prepare();
            // drop it on the wire!
            send(trace);
            logger.debug("Finished message sent");

            // add trace to ArrayList
            addToTraceList(new MessageContainer(EStates.CLIENT_FINISHED, trace.
                    getCurrentRecord(),
                    trace.getOldRecord(), false));
            sleepPoller(EStates.SERVER_FINISHED);
            runApplicationPhase = true;
            logger.debug("<<< TLS Handshake finished");
            
            if(enterApplicationPhase){
                logger.debug(">>> Enter application phase");
                switchToState(trace, EStates.APPLICATION);
                while(runApplicationPhase){
                    // TODO - due to timing issues in case of server alert if no renegotiation is allowed
                    try{
                        sleep(200);
                    }
                    catch(Exception e){
                    }
                    if((EStates.getStateById(getCurrentState()).equals(EStates.APPLICATION)) || (EStates.getStateById(getCurrentState()).equals(EStates.APPLICATION_PING))){
                        switchToState(trace, EStates.APPLICATION_PING);
                    }
                    else{
                        endApplicationPhase();
                    }
                }
            }
            logger.debug("<<< Application phase finished");
            fetcher.stopFetching();
        } catch (IOException e) {
            logger.debug("### Connection reset by peer.");
            closeSocket();
        }
    }
    
    /**
     * End application phase.
     */
    
    public void endApplicationPhase(){
        this.runApplicationPhase = false;
    }
    
    /**
     * Is workflow in application phase?
     */
    
    public boolean inApplicationPhase(){
        return enterApplicationPhase && runApplicationPhase;
    }
    
    /**
     * Get current messages
     */
    
    public ArrayList<ARecordFrame> getMessages(){
        if((responses == null) || responses.size() == 0)
            return null;
        ArrayList<ARecordFrame> result = new ArrayList<ARecordFrame>(responses.size());
        result.addAll(responses);
        responses.clear();
        return result;
    }
    
    /**
     * Add a message to received messages
     */
    
    public void addMessage(ARecordFrame msg){
        responses.add(msg);
    }
    
    /**
     * Get message builder
     */
    public MessageBuilder getMessageBuilder(){
        return msgBuilder;
    }
    
    /**
     * Reset message builder
     */
    public void resetMessageBuilder(){
        msgBuilder = new MessageBuilder();
    }

    /**
     * Poll the current state each 100 millis if the passed state is reached
     * yet.
     *
     * @param desiredState State to wait for
     * @throws IOException
     */
    private void sleepPoller(final EStates desiredState) throws IOException {
        while (getCurrentState() != desiredState.getID()) {
            if (getResponseThread().isAlive()) {
                try {
                    sleep(100);
                } catch (InterruptedException e) {
                    Thread.interrupted();
                }
            } else {
                throw new IOException("Response fetcher no longer reachable");
            }
        }
    }

    /**
     * Updates the current message hash.
     *
     * @param hashBuilder HashBuilder to be utilized
     * @param trace MessageContainer holding the record to hash
     */
    private synchronized void updateHash(final HandshakeHashBuilder hashBuilder,
            final MessageContainer trace) {
        byte[] message = trace.getCurrentRecordBytes();
        updateHash(hashBuilder, message);
    }

    /**
     * Updates the current message hash.
     *
     * @param hashBuilder HashBuilder to be utilized
     * @param encodedRecord Bytes of the encoded record
     */
    public void updateHash(final HandshakeHashBuilder hashBuilder,
            final byte[] encodedRecord) {
        hashBuilder.updateHash(encodedRecord,
                ARecordFrame.LENGTH_MINIMUM_ENCODED,
                encodedRecord.length - ARecordFrame.LENGTH_MINIMUM_ENCODED);
    }

    /**
     * Delivers one or multiple message(s) to the network layer.
     *
     * @param messages MessageContainer(s) to be send
     * @throws IOException
     */
    private void send(final MessageContainer... messages) throws
            IOException {
        ARecordFrame rec;
        byte[] msg;
        byte[][] byteBuffer = new byte[messages.length][];
        int overallCap = 0;

        if (out == null) {
            throw new IOException("Output stream not set");
        }

        // extract bytes of all messages
        for (int i = 0; i < messages.length; i++) {
            msg = messages[i].getCurrentRecordBytes();
            byteBuffer[i] = msg;
            overallCap += msg.length;
        }

        // put all bytes in one big byte array
        int pointer = 0;
        msg = new byte[overallCap];
        for (int i = 0; i < messages.length; i++) {
            System.arraycopy(byteBuffer[i], 0, msg, pointer,
                    byteBuffer[i].length);
            pointer += byteBuffer[i].length;
        }

        // send the data
        if (msg != null) {
            utils.sendMessage(out, msg);
            logger.debug("Message in hex: " + Utility.bytesToHex(msg));
        }
    }
 
    /**
     * Prepare and send records in application phase 
     * 
     * @param plain
     * @throws IllegalStateException 
     */
    
    public void applicationSendPlain(ARecordFrame plain) throws IllegalStateException{
        if(!runApplicationPhase){
            throw new IllegalStateException("Workflow is currently not in the application phase.");
        }else{
            MessageContainer trace = new MessageContainer();
            setRecordTrace(trace, plain);
            trace.prepare();
            try{
                send(trace);
            }catch(IOException e){
                //TODO
            }
        }
    }
    
    /**
     * Prepare, encrypt and send records in application phase 
     * 
     * @param plain
     * @throws IllegalStateException 
     */
    
    public void applicationSendEncrypted(ARecordFrame plain, boolean hashMessage) throws IllegalStateException{
        if(hashMessage == true)
            updateHash(hashBuilder, plain.getBytes());
        TLSCiphertext c = msgBuilder.encryptRecord(protocolVersion, plain, plain.getContentType());
        c.encode(true);
        applicationSendPlain(c);
    }
    
    /**
     * Get the PreMasterSecret.
     *
     * @return PreMasterSecret
     */
    public PreMasterSecret getPreMasterSecret() {
        return this.pms;
    }

    /**
     * Set the PreMasterSecret.
     */
    public void setPreMasterSecret(final PreMasterSecret pms) {
        this.pms = pms;
    }
    
    /**
     * Get the hash builder
     */
    public HandshakeHashBuilder getHashBuilder(){
        return this.hashBuilder;
    }

    /**
     * Get the handshake messages hash.
     *
     * @return handshakeHashes Hash of previous handshake messages
     */
    public byte[] getHash() {
        return this.handshakeHashes.clone();
    }
    
    /**
    * Set the handshake messages hash.
    */
    public void setHash(final byte[] hashes){
        handshakeHashes = hashes;
    }

    /**
     * Establish the connection to the test server.
     *
     * @param host Hostname of the server
     * @param port Port number of the server
     */
    public void connectToTestServer(final String host, final int port) {
        SocketAddress addr = new InetSocketAddress(host, port);
        try {
//            so.connect(addr, 1000);
//            so.setSoTimeout(100);
            so.connect(addr);
            out = so.getOutputStream();
            in = so.getInputStream();
        } catch (IOException e) {
            // TODO remove
            e.printStackTrace();
        }
    }

    /**
     * Checks whether timing measurement capabilites are enabled or not.
     *
     * @return True if time measurement is enabled.
     */
    public boolean isTimingEnabled() {
        return (this.so instanceof TimingSocket);
    }

    /**
     * Close the socket.
     */
    public void closeSocket() {
        if (out != null) {
            try {
                out.close();
            } catch (IOException e) {
                // TODO remove
                e.printStackTrace();
            } finally {
                out = null;
            }
        }
        if (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                // TODO remove
                e.printStackTrace();
            } finally {
                in = null;
            }
        }
        if (so != null) {
            try {
                so.close();
            } catch (IOException e) {
                // TODO remove
                e.printStackTrace();
            } finally {
                so = null;
            }
        }
    }

    /**
     * Is this workflow actually encrypted (yet).
     *
     * @return True if encrypted
     */
    public boolean isEncrypted() {
        return this.encrypted;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void update(final Observable o, final Object arg) {
        MessageContainer response = null;
        AResponseFetcher fetcher = null;
        if (o instanceof AResponseFetcher) {
            fetcher = (AResponseFetcher) o;
            response = (MessageContainer) arg;
        }
        //fetch the input bytes
        TLSResponse tlsResponse = new TLSResponse(response.getCurrentRecordBytes(), this);
        tlsResponse.handleResponse(response);
        if (getCurrentState() == EStates.ALERT.getID()) {
            logger.debug("### Connection reset due to FATAL_ALERT.");
            fetcher.stopFetching();
            closeSocket();
            return;
        }
        //hash current record
        if(!runApplicationPhase){
            updateHash(hashBuilder, response.getCurrentRecordBytes());
        }
        Thread.currentThread().interrupt();
    }
}