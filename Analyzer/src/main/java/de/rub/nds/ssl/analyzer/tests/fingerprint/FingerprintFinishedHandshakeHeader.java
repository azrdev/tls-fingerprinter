package de.rub.nds.ssl.analyzer.tests.fingerprint;

import de.rub.nds.ssl.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.analyzer.removeMe.TestConfiguration;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.analyzer.tests.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.KeyMaterial;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

public class FingerprintFinishedHandshakeHeader extends GenericFingerprintTest
        implements Observer {

    /**
     * Test counter.
     */
    private int counter = 1;

    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "handshakeHeader", invocationCount = 1)
    public void manipulateFinishedHandshakeHeader(String desc, byte[] msgType,
            byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.
                    info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setRecordLength(recordLength);
        parameters.setIdentifier(EFingerprintIdentifier.FinHandshakeHeader);
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
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
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
