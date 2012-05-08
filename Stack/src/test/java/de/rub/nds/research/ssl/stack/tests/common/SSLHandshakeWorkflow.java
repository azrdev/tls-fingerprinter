package de.rub.nds.research.ssl.stack.tests.common;

import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.*;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.*;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericStreamCipher;
import de.rub.nds.research.ssl.stack.tests.response.SSLResponse;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.AWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.WorkflowState;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.security.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
    private PublicKey pk = null;
    private Socket so = new Socket();
    private InputStream in = null;
    private OutputStream out = null;
    private SSLTestUtils utils = new SSLTestUtils();
    private EKeyExchangeAlgorithm keyExAlg;
    private ArrayList<Trace> traceList = new ArrayList<Trace>();
    private PreMasterSecret pms = null;
    private byte[] handshakeHashes = null;
    private boolean encrypted = false;

    /**
     * Define the workflow states.
     */
    public enum EStates implements WorkflowState {

        CLIENT_HELLO,
        SERVER_HELLO,
        CLIENT_CERTIFICATE,
        SERVER_CERTIFICATE,
        SERVER_KEY_EXCHANGE,
        SERVER_HELLO_DONE,
        CLIENT_KEY_EXCHANGE,
        CLIENT_CHANGE_CIPHER_SPEC,
        CLIENT_FINISHED,
        SERVER_CHANGE_CIPHER_SPEC,
        SERVER_FINISHED;
/**
 * TODO: this workflow fails!
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
 */
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
        SecurityParameters param = SecurityParameters.getInstance();
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        MessageBuilder msgBuilder = new MessageBuilder();
        Trace trace = new Trace();
        HandshakeHashBuilder hashBuilder = null;
        try {
            hashBuilder = new HandshakeHashBuilder();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        //create ClientHello message
        ClientHello clientHello = new ClientHello(protocolVersion);

        //set the cipher suites
        CipherSuites suites = new CipherSuites();
        suites.setSuites(new ECipherSuite[]{
                    ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
        clientHello.setCipherSuites(suites);
        clientHello.encode(true);

        //add the newly created message to the trace list
        trace.setCurrentRecord(clientHello);

        if (countObservers(EStates.CLIENT_HELLO) > 0) {
            trace.setOldRecord(clientHello);
        } else {
            trace.setOldRecord(null);
        }

        //invoke the observers
        previousState();
        notifyCurrentObservers(trace);

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

        //wait until input bytes are available
        this.waitForResponse();

        //fetch the response(s)
        getResponses(hashBuilder, trace);

        if (getCurrentState() != EStates.SERVER_HELLO_DONE.getID()) {
            this.waitForResponse();
            getResponses(hashBuilder, trace);
        }

        //cancel handshake processing if alert occurs
        if (traceList.get(traceList.size() - 1).getCurrentRecord() instanceof Alert) {
            return;
        }

        /*
         * Not all states might be run through in the server response. It has to
         * be assured that after server response ServerHelloDone state is
         * reached.
         */
        this.keyExAlg = keyParams.getKeyExchangeAlgorithm();
        this.pk = keyParams.getPublicKey();
        trace = new Trace();
        //create ClientKeyExchange
        ClientKeyExchange cke = new ClientKeyExchange(protocolVersion, keyExAlg);
        if (keyExAlg == EKeyExchangeAlgorithm.RSA) {
            pms = new PreMasterSecret(protocolVersion);
            //create encoded PMS
            byte[] encodedPMS = pms.encode(false);
            //encrypted PreMasterSecret
            EncryptedPreMasterSecret encPMS = new EncryptedPreMasterSecret(
                    encodedPMS, pk);
            cke.setExchangeKeys(encPMS);
        } else {
            ClientDHPublic clientDHPublic = new ClientDHPublic();
            byte[] generator = keyParams.getDHGenerator();
            byte[] primeModulus = keyParams.getDHPrime();
            byte[] privateValue = new byte[20];
            byte[] clientPublic = new byte[primeModulus.length];
            /*
             * generate a random private value
             */
            SecureRandom random = new SecureRandom();
            random.nextBytes(privateValue);

            BigInteger gen = new BigInteger(1, generator);
            BigInteger primeMod = new BigInteger(1, primeModulus);
            BigInteger priv = new BigInteger(1, privateValue);

            /*
             * compute clients DH public value g^x mod p
             */
            clientPublic = gen.modPow(priv, primeMod).toByteArray();

            byte[] tmp = new byte[primeModulus.length];

            if (clientPublic.length > primeModulus.length) {
                System.arraycopy(clientPublic, 1, tmp, 0, primeModulus.length);
                clientPublic = tmp;
            }
            clientDHPublic.setDhyc(clientPublic);
            cke.setExchangeKeys(clientDHPublic);
            pms = new PreMasterSecret(privateValue, keyParams.getDhPublic(),
                    primeModulus);
        }
        cke.encode(true);
        trace.setCurrentRecord(cke);

        if (countObservers(EStates.CLIENT_KEY_EXCHANGE) > 0) {
            trace.setOldRecord(cke);
        } else {
            trace.setOldRecord(null);
        }

        //change status and notify observers
        statusChanged(trace);

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
        trace.setCurrentRecord(ccs);
        statusChanged(trace);

        if (countObservers(EStates.CLIENT_CHANGE_CIPHER_SPEC) > 0) {
            trace.setOldRecord(ccs);
        } else {
            trace.setOldRecord(null);
        }

        ccs = (ChangeCipherSpec) trace.getCurrentRecord();
        msg = ccs.encode(true);
        utils.sendMessage(out, msg);
        encrypted = true;
        addToList(new Trace(EStates.CLIENT_CHANGE_CIPHER_SPEC, trace.getCurrentRecord(),
                trace.getOldRecord(), false));

        //set pre_master_secret
        byte[] pre_master_secret;
        if (keyParams.getKeyExchangeAlgorithm() == EKeyExchangeAlgorithm.RSA) {
            pre_master_secret = pms.encode(false);
        } else {
            pre_master_secret = pms.getDHKey();
        }

        //create the master secret
        MasterSecret masterSec = null;
        try {
            masterSec = new MasterSecret(param.getClientRandom(), param.
                    getServerRandom(), pre_master_secret);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        param.setMasterSecret(masterSec);

        //create the key material
        KeyMaterial keyMat = new KeyMaterial();

        //create Finished message
        Finished finished = msgBuilder.createFinished(protocolVersion,
                EConnectionEnd.CLIENT, handshakeHashes, masterSec);

        //encrypt Finished message
        String cipherName = param.getBulkCipherAlgorithm().toString();
        String macName = param.getMacAlgorithm().toString();
        SecretKey macKey = new SecretKeySpec(keyMat.getClientMACSecret(),
                macName);
        SecretKey symmKey = new SecretKeySpec(keyMat.getClientKey(), cipherName);
        TLSCiphertext rec = new TLSCiphertext(protocolVersion,
                EContentType.HANDSHAKE);
        if (param.getCipherType() == ECipherType.BLOCK) {
            GenericBlockCipher blockCipher = new GenericBlockCipher(finished);
            blockCipher.computePayloadMAC(macKey, macName);
            blockCipher.encryptData(symmKey, cipherName, keyMat.getClientIV());
            rec.setGenericCipher(blockCipher);
        } else if (param.getCipherType() == ECipherType.STREAM) {
            GenericStreamCipher streamCipher = new GenericStreamCipher(finished);
            streamCipher.computePayloadMAC(macKey, macName);
            streamCipher.encryptData(symmKey, cipherName);
            rec.setGenericCipher(streamCipher);
        }
        rec.encode(true);

        trace.setCurrentRecord(rec);

        if (countObservers(EStates.CLIENT_FINISHED) > 0) {
            trace.setOldRecord(rec);
        } else {
            trace.setOldRecord(null);
        }

        statusChanged(trace);

        rec = (TLSCiphertext) trace.getCurrentRecord();
        //send Finished message
        msg = rec.encode(true);
        utils.sendMessage(out, msg);

        addToList(new Trace(EStates.CLIENT_FINISHED, trace.getCurrentRecord(), trace.
                getOldRecord(), false));

        //wait until input bytes are available
        this.waitForResponse();

        getResponses(hashBuilder, trace);

        //cancel handshake processing if alert occurs
        if (traceList.get(traceList.size() - 1).getCurrentRecord() instanceof Alert) {
            return;
        }

        if (getCurrentState() == EStates.SERVER_CHANGE_CIPHER_SPEC.getID()) {
            this.waitForResponse();
            getResponses(hashBuilder, trace);
        }

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
     * Switches to the next state and notifies the observers.
     *
     * @param trace Holds the tracing data
     */
    public void statusChanged(Trace trace) {
        nextState();
        notifyCurrentObservers(trace);
    }

    /**
     * Process the response bytes
     *
     * @param hashBuilder Hash builder for hashing handshake messages
     * @param trace Trace
     */
    private void getResponses(HandshakeHashBuilder hashBuilder, Trace trace) {
        byte[] responseBytes = null;
        try {
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Wait for response bytes (max. 5s).
     */
    public void waitForResponse() {
        try {
            long startWait = System.currentTimeMillis();
            int timeout = 5000;
            while (in.available() == 0) {
                if (System.currentTimeMillis() > (startWait + timeout)) {
                    throw new SocketTimeoutException("No response within 5 sec");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
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
     * Get the negotiated key exchange algorithm.
     *
     * @return
     */
    public EKeyExchangeAlgorithm getKeyExAlgorithm() {
        return keyExAlg;
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
            so.connect(addr, 10000);
            out = so.getOutputStream();
            in = so.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
