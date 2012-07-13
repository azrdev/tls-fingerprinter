package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.util.Observable;
import java.util.Observer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.research.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.HeaderParameters;
import de.rub.nds.research.ssl.stack.tests.common.KeyMaterial;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import java.net.SocketException;

public class FingerprintFinishedHandshakeHeader implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private SSLTestUtils utils = new SSLTestUtils();
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Default protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test parameters
     */
    private HeaderParameters parameters = new HeaderParameters();
    static Logger logger = Logger.getRootLogger();

    @BeforeClass
    public void setUp() {
        PropertyConfigurator.configure("logging.properties");
    }

    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "handshakeHeader", invocationCount = 1)
    public void manipulateFinishedHandshakeHeader(String desc, byte[] msgType,
            byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new SSLHandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setRecordLength(recordLength);
        parameters.setTestClassName(this.getClass().getName());
        parameters.setDescription(desc);

        //start the handshake
        workflow.start();

        //analyze the handshake trace
        AFingerprintAnalyzer analyzer = new TestHashAnalyzer(parameters);
        analyzer.analyze(workflow.getTraceList());

        this.counter++;
        logger.info("++++Test finished.++++");
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
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states == EStates.CLIENT_FINISHED) {
            SecurityParameters param = SecurityParameters.getInstance();
            //create the key material
            KeyMaterial keyMat = new KeyMaterial();
            MasterSecret master = msgBuilder.createMasterSecret(workflow);
            Finished finished = msgBuilder.createFinished(
                    protocolVersion, EConnectionEnd.CLIENT, workflow.getHash(),
                    master);
            byte[] payload = finished.encode(true);
            //change msgType of the message
            if (parameters.getMsgType() != null) {
                byte[] msgType = parameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 0, msgType.length);
            }
            //change record length of the message
            if (parameters.getRecordLength() != null) {
                byte[] recordLength = parameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 1,
                        recordLength.length);
            }

            //encrypt Finished message
            String cipherName =
                    param.getBulkCipherAlgorithm().toString();
            String macName = param.getMacAlgorithm().toString();
            SecretKey macKey = new SecretKeySpec(
                    keyMat.getClientMACSecret(), macName);
            SecretKey symmKey = new SecretKeySpec(keyMat.getClientKey(),
                    cipherName);
            TLSCiphertext rec = new TLSCiphertext(protocolVersion,
                    EContentType.HANDSHAKE);
            GenericBlockCipher blockCipher = new GenericBlockCipher(
                    finished);
            blockCipher.computePayloadMAC(macKey, macName);

            if (payload != null) {
                try {
                    byte[] payloadMAC, plaintext;
                    payloadMAC = blockCipher.getMAC();
                    plaintext = blockCipher.concatenateDataMAC(payload,
                            payloadMAC);
                    Cipher symmCipher = blockCipher.initBlockCipher(
                            symmKey,
                            cipherName, keyMat.getClientIV());
                    byte[] paddedData, encryptedData = null;
                    int blockSize = symmCipher.getBlockSize();
                    paddedData = utils.addPadding(plaintext, blockSize,
                            false);
                    encryptedData = symmCipher.doFinal(paddedData);
                    rec.setGenericCipher(encryptedData);
                } catch (IllegalBlockSizeException e1) {
                    e1.printStackTrace();
                } catch (BadPaddingException e1) {
                    e1.printStackTrace();
                }
            }
            byte[] encrypted = rec.encode(true);
            //update the trace object
            trace.setCurrentRecordBytes(encrypted);
            trace.setCurrentRecord(rec);
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
    }
}
