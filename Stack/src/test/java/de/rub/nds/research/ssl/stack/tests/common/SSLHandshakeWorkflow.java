package de.rub.nds.research.ssl.stack.tests.common;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.*;
import de.rub.nds.research.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.*;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.tests.response.SSLResponse;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.AWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.WorkflowState;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.security.*;
import java.sql.Timestamp;
import java.util.ArrayList;

/**
 * The complete SSL Handshake workflow.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 13, 2012
 */
public class SSLHandshakeWorkflow extends AWorkflow {

    /**
     * Public constructor to initialize the workflow with its states.
     *
     * @param workflowStates The SSL handshake states
     */
    public SSLHandshakeWorkflow(WorkflowState[] workflowStates) {
        super(workflowStates);
    }
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    private Socket so = new Socket();
    private InputStream in = null;
    private OutputStream out = null;
    private SSLTestUtils utils = new SSLTestUtils();
    private ArrayList<Trace> traceList = new ArrayList<Trace>();
    private PreMasterSecret pms = null;
    private byte[] handshakeHashes = null;
    private boolean encrypted = false;

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
     * Initialize the handshake workflow with the state values
     */
    public SSLHandshakeWorkflow() {
        this(EStates.values());
    }

    /**
     * Executes the complete SSL handshake.
     */
    @Override
    public void start() {
        MessageBuilder msgBuilder = new MessageBuilder();
        Trace trace = new Trace();
        HandshakeHashBuilder hashBuilder = null;
        try {
            hashBuilder = new HandshakeHashBuilder();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //create the Client Hello message
        ClientHello clientHello = msgBuilder.createClientHello(protocolVersion); 
        setRecordTrace(trace, clientHello, EStates.CLIENT_HELLO);

        //switch the state of the handshake
        switchToPreviousState(trace);

        //set the probably changed message
        clientHello = (ClientHello) trace.getCurrentRecord();
        //save the client random value for later computations
        utils.setClientRandom(clientHello);
        //encode and send message
        byte[] msg = clientHello.encode(true);
        utils.sendMessage(out, msg);
        //hash current record
        hashBuilder.updateHash(msg, 5, msg.length - 5);
        
        //add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_HELLO, trace.getCurrentRecord(),
                trace.getOldRecord(), false));

        //fetch the response(s)
        try {
			getResponses(hashBuilder, trace);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}

        while (getCurrentState() != EStates.SERVER_HELLO_DONE.getID()) {
        	if (getCurrentState() == EStates.ALERT.getID()){
        		return;
        	}
        	else {
        		try {
					getResponses(hashBuilder, trace);
				} catch (IOException e) {
					e.printStackTrace();
					return;
				}
        	}
        }
        
        trace = new Trace();
        
        //create ClientKeyExchange
        ClientKeyExchange cke = msgBuilder.createClientKeyExchange(protocolVersion, this);
        cke.encode(true);
        setRecordTrace(trace, cke, EStates.CLIENT_KEY_EXCHANGE);

        //change status and notify observers
        switchToState(trace,EStates.CLIENT_KEY_EXCHANGE);

        cke = (ClientKeyExchange) trace.getCurrentRecord();
        msg = cke.encode(true);
        utils.sendMessage(out, msg);
        //hash current record
        hashBuilder.updateHash(msg, 5, msg.length - 5);
        //add trace to ArrayList
        addToList(new Trace(EStates.CLIENT_KEY_EXCHANGE, trace.getCurrentRecord(),
                trace.getOldRecord(), false));

        try {
            handshakeHashes = hashBuilder.getHandshakeMsgsHashes();
        } catch (DigestException e) {
            e.printStackTrace();
        }

        ChangeCipherSpec ccs = new ChangeCipherSpec(protocolVersion);
        ccs.encode(true);
        
        setRecordTrace(trace, ccs, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        
        switchToState(trace, EStates.CLIENT_CHANGE_CIPHER_SPEC);

        ccs = (ChangeCipherSpec) trace.getCurrentRecord();
        msg = ccs.encode(true);
        utils.sendMessage(out, msg);
        encrypted = true;
        addToList(new Trace(EStates.CLIENT_CHANGE_CIPHER_SPEC, trace.getCurrentRecord(),
                trace.getOldRecord(), false));

        //create the master secret
        MasterSecret masterSec = msgBuilder.createMasterSecret(this);

        //create Finished message
        Finished finished = msgBuilder.createFinished(protocolVersion,
                EConnectionEnd.CLIENT, handshakeHashes, masterSec);
        
        //encrypt finished message
        TLSCiphertext rec = msgBuilder.encryptRecord(protocolVersion, finished);
        rec.encode(true);

        setRecordTrace(trace, rec, EStates.CLIENT_FINISHED);

        switchToNextState(trace);

        rec = (TLSCiphertext) trace.getCurrentRecord();
        //send Finished message
        msg = rec.encode(true);
        utils.sendMessage(out, msg);

        addToList(new Trace(EStates.CLIENT_FINISHED, trace.getCurrentRecord(), trace.
                getOldRecord(), false));

        try {
			getResponses(hashBuilder, trace);
		} catch (IOException e1) {
			e1.printStackTrace();
			return;
		}

        if (getCurrentState() == EStates.SERVER_CHANGE_CIPHER_SPEC.getID()) {
            try {
				getResponses(hashBuilder, trace);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
        }

    }

    /**
     * Switches to the next state and notifies the observers.
     * @param trace Holds the tracing data
     */
    public void switchToNextState(Trace trace) {
        nextState();
        notifyCurrentObservers(trace);
    }
    
    /**
     * Sets a new state and notifies the observers.
     * @param trace Holds the tracing data
     * @param state The new state
     */
    public void switchToState(Trace trace, EStates state) {
        setCurrentState(state.getID());
        notifyCurrentObservers(trace);
    }
    
    /**
     * Switches to the previous state or holds current state if 
     * it is the first state.
     * @param trace Holds the tracing data
     */
    public void switchToPreviousState(Trace trace) {
    	previousState();
        notifyCurrentObservers(trace);
    }
    
    private void setRecordTrace(Trace trace,
    		ARecordFrame record, EStates state) {
    	//add the newly created message to the trace list
        trace.setCurrentRecord(record);

        if (countObservers(state) > 0) {
            trace.setOldRecord(record);
        } else {
            trace.setOldRecord(null);
        }
    }
    

    /**
     * Process the response bytes
     *
     * @param hashBuilder Hash builder for hashing handshake messages
     * @param trace Trace
     * @throws IOException 
     */
    private void getResponses(HandshakeHashBuilder hashBuilder, Trace trace) throws IOException {
    	//wait until response bytes are available
    	byte[] responseBytes = null;
    	waitForResponse();
    	while (in.available() != 0) {
    		trace = new Trace();
    		//set the Timestamp and exact time of message arrival
    		trace.setTimestamp(new Timestamp(System.currentTimeMillis()));
    		trace.setNanoTime(System.nanoTime());
    		//fetch the input bytes
    		responseBytes = utils.fetchResponse(in);
    		SSLResponse response = new SSLResponse(responseBytes, this);
    		response.handleResponse(trace, responseBytes);
    		//hash current record
    		hashBuilder.updateHash(responseBytes, 5,
    				responseBytes.length - 5);
    	}
    }
    
    /**
     * Serialize traceList and write it to file.
     */
    public void saveSerializedTraceList() {
//		OutputStream fileOutStream = null;
//		try {
//			fileOutStream = new FileOutputStream("eugenTest.ser");
//			ObjectOutputStream oStream = new ObjectOutputStream(fileOutStream);
//			oStream.writeObject(this.traceList);
//			fileOutStream.close();
//		} catch (FileNotFoundException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
    }

    /**
     * Wait for response bytes (max. 500ms).
     * @throws IOException 
     */
    public void waitForResponse() throws IOException {
    	long startWait = System.currentTimeMillis();
    	int timeout = 500;
    	while (in.available() == 0) {
    		// TODO: Sehen wir hier irgendeine Möglichkeit, mehr CPU-Zeit zu verbrauchen?
    		if (System.currentTimeMillis() > (startWait + timeout)) {
    			throw new SocketTimeoutException("No response within 500 ms");
    		}
    	}
    }

    /**
     * Add a new Trace object to the ArrayList.
     *
     * @param trace
     */
    public void addToList(Trace trace) {
        this.traceList.add(trace);
    }

    /**
     * Get the trace list of the whole handshake.
     *
     * @return Trace list
     */
    public ArrayList<Trace> getTraceList() {
        return traceList;
    }

    /**
     * Get the Socket of the connection.
     *
     * @return Socket
     */
    public Socket getSocket() {
        return so;
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
    public void setPreMasterSecret(PreMasterSecret pms) {
        this.pms = pms;
    }

    /**
     * Get the handshake messages hash.
     *
     * @return handshakeHashes Hash of previous handshake messages
     */
    public byte[] getHash() {
        return this.handshakeHashes;
    }

    public boolean isEncrypted() {
        return this.encrypted;
    }

    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }

    /**
     * Establish the connection to the test server
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
}
