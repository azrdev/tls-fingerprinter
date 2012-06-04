package de.rub.nds.research.ssl.stack.tests.common;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.tests.fingerprint.FingerprintClientHello;
import de.rub.nds.research.ssl.stack.tests.response.SSLResponse;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.AWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.WorkflowState;
import de.rub.nds.research.timingsocket.TimingSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;

import org.apache.log4j.Logger;

/**
 * The complete SSL Handshake workflow.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Apr 13, 2012
 */
public final class SSLHandshakeWorkflow extends AWorkflow {

    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    private Socket so = null;
    private InputStream in = null;
    private OutputStream out = null;
    private SSLTestUtils utils = new SSLTestUtils();
    private ArrayList<Trace> traceList = new ArrayList<Trace>();
    private PreMasterSecret pms = null;
    private byte[] handshakeHashes = null;
    private boolean encrypted = false;
    private boolean timingEnabled = false;
    private boolean waitingForTime = false;
    
    static Logger logger = Logger.getRootLogger();

    /**
     * Define the workflow states.
     */
    public enum EStates implements WorkflowState {

//        CLIENT_HELLO,
//        SERVER_HELLO,
//        CLIENT_CERTIFICATE,
//        SERVER_CERTIFICATE,
//        SERVER_KEY_EXCHANGE,
//        SERVER_HELLO_DONE,
//        CLIENT_KEY_EXCHANGE,
//        CLIENT_CHANGE_CIPHER_SPEC,
//        CLIENT_FINISHED,
//        SERVER_CHANGE_CIPHER_SPEC,
//        SERVER_FINISHED;
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
        ALERT;

        @Override
        public int getID() {
            return this.ordinal();
        }

        public static EStates getStateById(int id) {
            EStates[] states = EStates.values();
            return states[id];
        }
    }

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param workflowStates The SSL handshake states
     * @param enableTiming Enable time measurement capabilities
     */
    public SSLHandshakeWorkflow(WorkflowState[] workflowStates,
            boolean enableTiming) {
        super(workflowStates);
        if (enableTiming) {
            try {
                so = new TimingSocket();
                timingEnabled = true;
            } catch (SocketException e) {
                e.printStackTrace();
            }
        } else {
            so = new Socket();
        }
    }

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param enableTiming Enable time measurement capabilities
     */
    public SSLHandshakeWorkflow(boolean enableTiming) {
        this(EStates.values(), enableTiming);
    }

    /**
     * Initialize the handshake workflow with the state values
     */
    public SSLHandshakeWorkflow() {
        this(EStates.values(), false);
    }

    /**
     * Executes the complete SSL handshake.
     */
    @Override
    public void start() {
    	logger.info(">>> Start TLS handshake");
        ARecordFrame record;
        Trace trace;
        MessageBuilder msgBuilder = new MessageBuilder();
        HandshakeHashBuilder hashBuilder = null;
        try {
            hashBuilder = new HandshakeHashBuilder();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        /*
         * create the ClientHello
         */
        trace = new Trace();
        record = msgBuilder.createClientHello(protocolVersion);
        setRecordTrace(trace, record);
        // switch the state of the handshake
        switchToPreviousState(trace);
        // set the probably changed message
        record = trace.getCurrentRecord();
        // save the client random value for later computations
        utils.setClientRandom((ClientHello) record);
        // drop it on the wire!
        prepareAndSend(trace);
        logger.info("Client Hello message send");
        // hash current record
        updateHash(hashBuilder, trace);
        // add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_HELLO, trace.getCurrentRecord(),
                trace.getOldRecord(), false));
        // fetch the response(s)
        while (getCurrentState() != EStates.SERVER_HELLO_DONE.getID()) {
            if (getCurrentState() == EStates.ALERT.getID()) {
                return;
            }

            try {
                getResponses(hashBuilder);
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }

        /*
         * create ClientKeyExchange
         */
        trace = new Trace();
        record = msgBuilder.createClientKeyExchange(protocolVersion, this);
        setRecordTrace(trace, record);
        // change status and notify observers
        switchToState(trace, EStates.CLIENT_KEY_EXCHANGE);
        // drop it on the wire!
        prepareAndSend(trace);
        logger.info("Client Key Exchange message send");
        logger.debug("Message in hex: " + Utility.byteToHex(trace.getCurrentRecord().getPayload()));
        // hash current record
        updateHash(hashBuilder, trace);
        // add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_KEY_EXCHANGE,
                trace.getCurrentRecord(),
                trace.getOldRecord(), false));

        /*
         * create ChangeCipherSepc
         */
        trace = new Trace();
        record = new ChangeCipherSpec(protocolVersion);
        setRecordTrace(trace, record);
        //change status and notify observers
        switchToState(trace, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        // drop it on the wire!
        prepareAndSend(trace);
        logger.info("Change Cipher Spec message send");
        logger.debug("Message in hex: " + Utility.byteToHex(trace.getCurrentRecord().getPayload()));
        // switch to encrypted mode
        encrypted = true;
        // add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_CHANGE_CIPHER_SPEC, trace.
                getCurrentRecord(),
                trace.getOldRecord(), false));

        /*
         * create Finished
         */
        trace = new Trace();
        // create the master secret
        MasterSecret masterSec = msgBuilder.createMasterSecret(this);
        // hash handshake messages
        try {
            handshakeHashes = hashBuilder.getHandshakeMsgsHashes();
        } catch (DigestException e) {
            e.printStackTrace();
        }
        record = msgBuilder.createFinished(protocolVersion,
                EConnectionEnd.CLIENT, handshakeHashes, masterSec);
        record = msgBuilder.encryptRecord(protocolVersion, record);
        setRecordTrace(trace, record);
        // change status and notify observers
        switchToNextState(trace);
        // drop it on the wire!
        prepareAndSend(trace);
        logger.info("Finished message send");
        logger.debug("Message in hex: " + Utility.byteToHex(trace.getCurrentRecord().getPayload()));
        // add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_FINISHED, trace.getCurrentRecord(),
                trace.getOldRecord(), false));
        // fetch the response(s)
        while (getCurrentState() != EStates.SERVER_FINISHED.getID()) {
            if (getCurrentState() == EStates.ALERT.getID()) {
                return;
            }

            try {
                getResponses(hashBuilder);
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
        logger.info("<<< TLS Handshake finished");
    }

    /**
     * Updates the current message hash.
     *
     * @param hashBuilder HashBuilder to be utilized
     * @param trace Trace holding the record to hash
     */
    private void updateHash(final HandshakeHashBuilder hashBuilder,
            final Trace trace) {
        byte[] message = trace.getCurrentRecordBytes();
        updateHash(hashBuilder, message);
    }

    /**
     * Updates the current message hash.
     *
     * @param hashBuilder HashBuilder to be utilized
     * @param encodedRecord Bytes of the encoded record
     */
    private void updateHash(final HandshakeHashBuilder hashBuilder,
            final byte[] encodedRecord) {
        hashBuilder.updateHash(encodedRecord,
                ARecordFrame.LENGTH_MINIMUM_ENCODED,
                encodedRecord.length - ARecordFrame.LENGTH_MINIMUM_ENCODED);
    }

    /**
     * Prepares the trace and delivers it to the network layer.
     *
     * @param trace Trace to be send
     */
    private void prepareAndSend(final Trace trace) {
        ARecordFrame rec;
        byte[] msg;

        // do we need accurate response times?
        if (timingEnabled && trace.isTimeMeasurementEnabled()) {
            waitingForTime = true;
            ((TimingSocket) so).startTimeMeasurement();
        }

        // try sending raw bytes - if no present yet, encode!
        msg = trace.getCurrentRecordBytes();
        if (msg == null) {
            rec = trace.getCurrentRecord();
            msg = rec.encode(true);
            trace.setCurrentRecordBytes(msg);
        }
        utils.sendMessage(out, msg);
        logger.debug("Message in hex: " + Utility.byteToHex(msg));
    }

    /**
     * Switches to the next state and notifies the observers.
     *
     * @param trace Holds the tracing data
     */
    public void switchToNextState(final Trace trace) {
        nextState();
        notifyCurrentObservers(trace);
    }

    /**
     * Sets a new state and notifies the observers.
     *
     * @param trace Holds the tracing data
     * @param state The new state
     */
    public void switchToState(final Trace trace, final EStates state) {
        setCurrentState(state.getID());
        notifyCurrentObservers(trace);
    }

    /**
     * Switches to the previous state or holds current state if it is the first
     * state.
     *
     * @param trace Holds the tracing data
     */
    public void switchToPreviousState(final Trace trace) {
        previousState();
        notifyCurrentObservers(trace);
    }

    /**
     * Sets the current record of a trace and saves the previous one if present.
     *
     * @param trace Trace to be modified
     * @param record New record to be set
     */
    private void setRecordTrace(final Trace trace,
            final ARecordFrame record) {
        // save the old state
        ARecordFrame oldRecord = trace.getOldRecord();
        trace.setOldRecord(oldRecord);

        //add the newly created message to the trace list
        trace.setCurrentRecord(record);
    }

    /**
     * Process the response bytes.
     *
     * @param hashBuilder Hash builder for hashing handshake messages
     * @throws IOException On I/O error
     */
    private void getResponses(final HandshakeHashBuilder hashBuilder)
            throws IOException {
        //wait until response bytes are available
        byte[] responseBytes = null;
        waitForResponse();
        do {
            Trace trace = new Trace();
            //set the Timestamp and exact time of message arrival
            trace.setTimestamp(new Timestamp(System.currentTimeMillis()));
            trace.setNanoTime(System.nanoTime());

            if (timingEnabled && waitingForTime) {
                waitingForTime = false;
               trace.setAccurateTime(((TimingSocket) so).getTiming());
            }
            
            //fetch the input bytes
            responseBytes = utils.fetchResponse(in);
            SSLResponse response = new SSLResponse(responseBytes, this);
            response.handleResponse(trace, responseBytes);
            //hash current record
            updateHash(hashBuilder, responseBytes);
        } while (in.available() != 0);
    }

    /**
     * Wait for response bytes (max. 500ms).
     *
     * @throws IOException On I/O error
     */
    private void waitForResponse() throws IOException {
        long startWait = System.currentTimeMillis();
        final int timeout = 500;
        while (in.available() == 0) {
            // TODO: Sehen wir hier irgendeine Möglichkeit, mehr CPU-Zeit zu verbrauchen?
            if (System.currentTimeMillis() > (startWait + timeout)) {
                throw new SocketTimeoutException("No response within " + timeout + " ms");
            }
        }
    }

    /**
     * Add a new Trace object to the ArrayList.
     *
     * @param trace Trace object to be added
     */
    public void addToList(final Trace trace) {
        this.traceList.add(trace);
    }

    /**
     * Get the trace list of the whole handshake.
     *
     * @return Trace list
     */
    public ArrayList<Trace> getTraceList() {
        return (ArrayList<Trace>) traceList.clone();
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
     * Get the handshake messages hash.
     *
     * @return handshakeHashes Hash of previous handshake messages
     */
    public byte[] getHash() {
        return this.handshakeHashes.clone();
    }

    /**
     * Establish the connection to the test server.
     *
     * @param host Hostname of the server
     * @param port Port number of the server
     */
    public void connectToTestServer(String host, int port) {
        SocketAddress addr;
        addr = new InetSocketAddress(host, port);
        try {
            // TODO: Interessante werte für timeout...
            so.connect(addr, 100);
            so.setSoTimeout(100);
            out = so.getOutputStream();
            in = so.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Checks whether timing measurement capabilites are enabled or not.
     *
     * @return True if time measurement is enabled.
     */
    public boolean isTimingEnabled() {
        return this.timingEnabled;
    }

    /**
     * Close the socket.
     *
     * @throws IOException On I/O error
     */
    public void closeSocket() throws IOException {
        if (so != null) {
            so.close();
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
}
