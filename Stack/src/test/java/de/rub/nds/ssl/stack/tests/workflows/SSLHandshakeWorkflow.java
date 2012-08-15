package de.rub.nds.ssl.stack.tests.workflows;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.tests.common.HandshakeHashBuilder;
import de.rub.nds.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.ssl.stack.tests.response.ResponseFetcher;
import de.rub.nds.ssl.stack.tests.response.SSLResponse;
import de.rub.nds.ssl.stack.tests.trace.MessageTrace;
import de.rub.nds.virtualnetworklayer.connection.Connection.Trace;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.socket.VNLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.*;
import org.apache.log4j.Logger;

/**
 * The complete SSL Handshake workflow.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Apr 13, 2012
 */
public final class SSLHandshakeWorkflow extends AWorkflow implements Observer {

    /**
     * Response fetcher Thread.
     */
    private Thread respFetchThread;
    /**
     * Main thread.
     */
    private Thread mainThread;
    private final EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    private Socket so = null;
    private InputStream in = null;
    private OutputStream out = null;
    private SSLTestUtils utils = new SSLTestUtils();
    private ArrayList<MessageTrace> traceList = new ArrayList<MessageTrace>();
    List<MessageTrace> list = Collections.synchronizedList(traceList);
    private PreMasterSecret pms = null;
    private byte[] handshakeHashes = null;
    private boolean encrypted = false;
    private boolean vnlEnabled = false;
    private final static Logger logger = Logger.getRootLogger();
    private HandshakeHashBuilder hashBuilder = null;

    /**
     * Define the workflow states.
     */
    public enum EStates implements WorkflowState {

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
     * @param enableVNL Enable the virtual network layer
     */
    public SSLHandshakeWorkflow(WorkflowState[] workflowStates,
            boolean enableVNL) throws SocketException {
        super(workflowStates);
        vnlEnabled = enableVNL;

        if (vnlEnabled) {
//            so = new VNLSocket();
        } else {
            so = new Socket();
        }
    }

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param enableTiming Enable time measurement capabilities
     */
    public SSLHandshakeWorkflow(boolean enableTiming) throws SocketException {
        this(EStates.values(), enableTiming);
    }

    /**
     * Initialize the handshake workflow with the state values
     */
    public SSLHandshakeWorkflow() throws SocketException {
        this(EStates.values(), false);
    }

    /**
     * Executes the complete SSL handshake.
     */
    @Override
    public void start() {
        try {
            logger.debug(">>> Start TLS handshake");
            ResponseFetcher fetcher = new ResponseFetcher(this.so, this);
            respFetchThread = new Thread(fetcher);
            respFetchThread.start();
            setMainThread(Thread.currentThread());
            ARecordFrame record;
            MessageTrace trace;
            MessageBuilder msgBuilder = new MessageBuilder();
            try {
                hashBuilder = new HandshakeHashBuilder();
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }

            /*
             * create the ClientHello
             */
            trace = new MessageTrace();
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
            logger.debug("Client Hello message sent");
            // hash current record
            updateHash(hashBuilder, trace);
            // add trace to ArrayList
            addToList(new MessageTrace(EStates.CLIENT_HELLO, trace.
                    getCurrentRecord(),
                    trace.getOldRecord(), false));
            sleepPoller(EStates.SERVER_HELLO_DONE);

            /*
             * create ClientKeyExchange
             */
            trace = new MessageTrace();
            record = msgBuilder.createClientKeyExchange(protocolVersion, this);
            setRecordTrace(trace, record);
            // change status and notify observers
            switchToState(trace, EStates.CLIENT_KEY_EXCHANGE);
            // drop it on the wire!
            prepareAndSend(trace);
            logger.debug("Client Key Exchange message sent");
            // add trace to ArrayList
            addToList(new MessageTrace(EStates.CLIENT_KEY_EXCHANGE,
                    trace.getCurrentRecord(),
                    trace.getOldRecord(), false));
            // hash current record
            updateHash(hashBuilder, trace);

            /*
             * create ChangeCipherSepc
             */
            trace = new MessageTrace();
            record = new ChangeCipherSpec(protocolVersion);
            setRecordTrace(trace, record);
            //change status and notify observers
            switchToState(trace, EStates.CLIENT_CHANGE_CIPHER_SPEC);
            // drop it on the wire!
            prepareAndSend(trace);
            logger.debug("Change Cipher Spec message sent");
            // switch to encrypted mode
            encrypted = true;
            // add trace to ArrayList
            addToList(new MessageTrace(EStates.CLIENT_CHANGE_CIPHER_SPEC, trace.
                    getCurrentRecord(),
                    trace.getOldRecord(), false));

            /*
             * create Finished
             */
            trace = new MessageTrace();
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
            switchToState(trace, EStates.CLIENT_FINISHED);
            // drop it on the wire!
            prepareAndSend(trace);
            logger.debug("Finished message sent");
            // add trace to ArrayList
            addToList(new MessageTrace(EStates.CLIENT_FINISHED, trace.
                    getCurrentRecord(),
                    trace.getOldRecord(), false));
            sleepPoller(EStates.SERVER_FINISHED);

            fetcher.stopFetching();
            logger.debug("<<< TLS Handshake finished");
        } catch (IOException e) {
            logger.debug("### Connection reset by peer.");
            closeSocket();
        }
    }

    /**
     * Poll the current state each 100 millis if the passed state is 
     * reached yet.
     *
     * @param desiredState State to wait for
     */
    private void sleepPoller(final EStates desiredState) throws IOException {
        while (getCurrentState() != desiredState.getID()) {
            if (respFetchThread.isAlive()) {
                try {
                    Thread.sleep(100);
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
     * @param trace MessageTrace holding the record to hash
     */
    private synchronized void updateHash(final HandshakeHashBuilder hashBuilder,
            final MessageTrace trace) {
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
     * Get the Thread of the handshake workflow.
     *
     * @return Workflow thread.
     */
    public void wakeUp() {
        this.mainThread.interrupt();
    }

    /**
     * Set the main Thread.
     *
     * @param thread Main Thread
     */
    public void setMainThread(Thread thread) {
        this.mainThread = thread;
    }

    /**
     * Get the main Thread.
     *
     * @return Main thread
     */
    public Thread getMainThread() {
        return this.mainThread;
    }

    /**
     * Prepares the trace and delivers it to the network layer.
     *
     * @param trace MessageTrace to be send
     */
    private void prepareAndSend(final MessageTrace trace) throws IOException {
        ARecordFrame rec;
        byte[] msg;

        if (out == null) {
            throw new IOException("Output stream not set");
        }

        // try sending raw bytes - if no present yet, encode!
        msg = trace.getCurrentRecordBytes();
        if (msg == null) {
            rec = trace.getCurrentRecord();
            msg = rec.encode(true);
            trace.setCurrentRecordBytes(msg);
        }
        utils.sendMessage(out, msg);
        logger.debug("Message in hex: " + Utility.bytesToHex(msg));
    }

    /**
     * Switches to the next state and notifies the observers.
     *
     * @param trace Holds the tracing data
     */
    public void switchToNextState(final MessageTrace trace) {
        nextState();
        notifyCurrentObservers(trace);
    }

    /**
     * Sets a new state and notifies the observers.
     *
     * @param trace Holds the tracing data
     * @param state The new state
     */
    public void switchToState(final MessageTrace trace, final EStates state) {
        setCurrentState(state.getID());
        notifyCurrentObservers(trace);
    }

    /**
     * Switches to the previous state or holds current state if it is the first
     * state.
     *
     * @param trace Holds the tracing data
     */
    public void switchToPreviousState(final MessageTrace trace) {
        previousState();
        notifyCurrentObservers(trace);
    }

    /**
     * Sets the current record of a trace and saves the previous one if present.
     *
     * @param trace MessageTrace to be modified
     * @param record New record to be set
     */
    private void setRecordTrace(final MessageTrace trace,
            final ARecordFrame record) {
        // save the old state
        ARecordFrame oldRecord = trace.getOldRecord();
        trace.setOldRecord(oldRecord);

        //add the newly created message to the trace list
        trace.setCurrentRecord(record);
    }

    /**
     * Add a new MessageTrace object to the ArrayList.
     *
     * @param trace MessageTrace object to be added
     */
    public synchronized void addToList(final MessageTrace trace) {
        list.add(trace);
    }

    /**
     * Get the trace list of the whole handshake.
     *
     * @return MessageTrace list
     */
    public ArrayList<MessageTrace> getTraceList() {
        return (ArrayList<MessageTrace>) traceList.clone();
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
        SocketAddress addr = new InetSocketAddress(host, port);
        try {
            so.connect(addr, 1000);
//            so.setSoTimeout(100);
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
        return this.vnlEnabled;
    }

    /**
     * Close the socket.
     *
     * @throws IOException On I/O error
     */
    public void closeSocket() {
        if (out != null) {
            try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                out = null;
            }
        }
        if (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                in = null;
            }
        }
        if (so != null) {
            try {
                so.close();
            } catch (IOException e) {
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
    public void update(Observable o, Object arg) {
        byte[] responseBytes = null;
        ResponseFetcher fetcher = null;
        if (o instanceof ResponseFetcher) {
            fetcher = (ResponseFetcher) o;
            responseBytes = (byte[]) arg;
        }
        MessageTrace trace = new MessageTrace();
        //set the Timestamp and exact time of message arrival
        trace.setTimestamp(new Timestamp(System.currentTimeMillis()));
        trace.setNanoTime(System.nanoTime());
        if (vnlEnabled) {
            // ################################################################
            // TODO
            Trace<Packet> packetTrace = ((VNLSocket) so).getTrace();
            int pos = packetTrace.size();
            trace.setVNLTime(packetTrace.get(pos).getTimeStamp());
            // ################################################################
        }

        //fetch the input bytes
        SSLResponse response = new SSLResponse(responseBytes, this);
        response.handleResponse(trace, responseBytes);
        if (getCurrentState() == EStates.ALERT.getID()) {
            logger.debug("### Connection reset due to FATAL_ALERT.");
            fetcher.stopFetching();
            closeSocket();
            return;
        }
        //hash current record
        updateHash(hashBuilder, responseBytes);
        Thread.currentThread().interrupt();
    }

    /**
     * Getter for VNL Socket access.
     *
     * @return Returns the VNLSocket if VNL is active.
     * @throws IllegalStateException If VNL has not been enabled when
     * constructor was called.
     */
    public VNLSocket getVNLSocket() throws IllegalStateException {
        if (!vnlEnabled || !(so instanceof VNLSocket)) {
            throw new IllegalStateException("Virtual Network Layer not active.");
        }

        return (VNLSocket) so;
    }
}
