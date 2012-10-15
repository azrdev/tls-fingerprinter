package de.rub.nds.ssl.stack.tests.fingerprint;

import java.net.SocketException;
import java.security.InvalidKeyException;
import java.util.Observable;
import java.util.Observer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.FinishedParameters;
import de.rub.nds.ssl.stack.workflows.commons.KeyMaterial;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.trace.MessageTrace;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;

public class FingerprintFinished extends GenericFingerprintTest implements Observer {

    /**
     * Test parameters.
     */
    private FinishedParameters parameters = new FinishedParameters();

    @DataProvider(name = "finished")
    public Object[][] createFinishedData() {
        return new Object[][]{
                {"Wrong padding", true, false, false, false, false},
                {"Destroy MAC", false, true, false, false, false},
    		 	{"Destroy hash value", false, false, true, false, false},
    		 	{"Destroy Verify", false, false, false, true, false},
    		 	{"Change length byte of padding", false, false, false, false, true}
        };
    }
    
    @Test(enabled = true, dataProvider = "finished", invocationCount = 1)
    public void manipulateFinishedRecordHeader(String desc, boolean changePadding, boolean destroyMAC,
    		boolean destroyHash, boolean destroyVerify, boolean changePadLength) throws SocketException {
    	logger.info("++++Start Test No." + counter + "(" + desc +")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
        	workflow.connectToTestServer(HOST, PORT);
        	logger.info("Test Server: " + HOST +":" +PORT);
        }
        else {
        	workflow.connectToTestServer(TestConfiguration.HOST,
        			TestConfiguration.PORT);
        	logger.info("Test Server: " + TestConfiguration.HOST +":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");
        
        //set the test parameters
        parameters.setDestroyMAC(destroyMAC);
        parameters.setDestroyHash(destroyHash);
        parameters.setDestroyVerify(destroyVerify);
        parameters.setChangePadLength(changePadLength);
        parameters.setChangePadding(changePadding);
        parameters.setIdentifier(EFingerprintIdentifier.Finished);
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
        MessageTrace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageTrace) arg;
        }
        if (states == EStates.CLIENT_FINISHED) {
        	 SecurityParameters param = SecurityParameters.getInstance();
             byte[] handshakeHashes = workflow.getHash();
             if (parameters.isDestroyHash()){
            	 handshakeHashes[5]=(byte)0x00;
             }
             //create the key material
             KeyMaterial keyMat = new KeyMaterial();

             //create Finished message
             byte[] data = null;
             Finished finished = new Finished(protocolVersion,
                     EConnectionEnd.CLIENT);
             if (param.getMasterSecret() != null
                     && handshakeHashes != null) {
                 try {
                     finished.createVerifyData(param.getMasterSecret(),
                             handshakeHashes);
                     data = finished.encode(true);
                     if (parameters.isDestroyVerify()){
                    	 data[8]=(byte)0x00;
                     }
                 } catch (InvalidKeyException e1) {
                     e1.printStackTrace();
                 }
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

             if (data != null) {
                 try {
                     byte[] payloadMAC, plaintext;
                     payloadMAC = blockCipher.getMAC();
                     if (parameters.isDestroyMAC()){
                    	 payloadMAC[5]=(byte)0x00;
                     }
                     plaintext = blockCipher.concatenateDataMAC(data,
                             payloadMAC);
                     Cipher symmCipher = blockCipher.initBlockCipher(
                             symmKey,
                             cipherName, keyMat.getClientIV());
                     byte[] paddedData, encryptedData = null;
                     int blockSize = symmCipher.getBlockSize();
                     paddedData = utils.addPadding(plaintext, blockSize,
                             parameters.isChangePadding());
                     if(parameters.isChangePadLength()){
                    	 paddedData[paddedData.length-1]=0x00;
                    	 logger.debug("Padded data: " + Utility.bytesToHex(paddedData));
                     }
                     encryptedData = symmCipher.doFinal(paddedData);
                     rec.setGenericCipher(encryptedData);
                 } catch (IllegalBlockSizeException e1) {
                     e1.printStackTrace();
                 } catch (BadPaddingException e1) {
                     e1.printStackTrace();
                 }
             }
             byte [] payload = rec.encode(true);
             //update the trace object
             trace.setCurrentRecordBytes(payload);
             trace.setCurrentRecord(finished);
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
