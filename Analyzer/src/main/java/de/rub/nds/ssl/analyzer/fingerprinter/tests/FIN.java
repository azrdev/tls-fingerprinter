package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.analyzer.parameters.FinishedParameters;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.KeyMaterial;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FIN extends AGenericFingerprintTest implements Observer {

    /**
     * Test headerParameters.
     */
    private FinishedParameters finParameters = new FinishedParameters();

    public ResultWrapper manipulateFinishedRecordHeader(String desc,
            boolean changePadding, boolean destroyMAC,
            boolean destroyHash, boolean destroyVerify, boolean changePadLength)
            throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test headerParameters
        finParameters.setDestroyMAC(destroyMAC);
        finParameters.setDestroyHash(destroyHash);
        finParameters.setDestroyVerify(destroyVerify);
        finParameters.setChangePadLength(changePadLength);
        finParameters.setChangePadding(changePadding);
        finParameters.setIdentifier(EFingerprintIdentifier.Finished);
        finParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(finParameters, workflow.getTraceList());
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
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
            byte[] handshakeHashes = workflow.getHash();
            if (finParameters.isDestroyHash()) {
                handshakeHashes[5] = (byte) 0x00;
            }
            //create the key material
            KeyMaterial keyMat = new KeyMaterial();

            //create FIN message
            byte[] data = null;
            Finished finished = new Finished(protocolVersion,
                    EConnectionEnd.CLIENT);
            if (param.getMasterSecret() != null
                    && handshakeHashes != null) {
                try {
                    finished.createVerifyData(param.getMasterSecret(),
                            handshakeHashes);
                    data = finished.encode(true);
                    if (finParameters.isDestroyVerify()) {
                        data[8] = (byte) 0x00;
                    }
                } catch (InvalidKeyException e1) {
                    logger.error("Invalid key.", e1);
                }
            }

            //encrypt FIN message
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
                    if (finParameters.isDestroyMAC()) {
                        payloadMAC[5] = (byte) 0x00;
                    }
                    plaintext = blockCipher.concatenateDataMAC(data,
                            payloadMAC);
                    Cipher symmCipher = blockCipher.initBlockCipher(
                            symmKey,
                            cipherName, keyMat.getClientIV());
                    byte[] paddedData, encryptedData = null;
                    int blockSize = symmCipher.getBlockSize();
                    paddedData = utils.addPadding(plaintext, blockSize,
                            finParameters.isChangePadding());
                    if (finParameters.isChangePadLength()) {
                        paddedData[paddedData.length - 1] = 0x00;
                        logger.debug("Padded data: " + Utility.bytesToHex(
                                paddedData));
                    }
                    encryptedData = symmCipher.doFinal(paddedData);
                    rec.setGenericCipher(encryptedData);
                } catch (IllegalBlockSizeException e1) {
                    logger.error("Wrong blocksize.", e1);
                } catch (BadPaddingException e1) {
                    logger.error("Invalid padding.", e1);
                }
            }
            byte[] payload = rec.encode(true);
            //update the trace object
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(finished);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Wrong padding", true, false, false, false, false},
            {"Destroy MAC", false, true, false, false, false},
            {"Destroy hash value", false, false, true, false, false},
            {"Destroy Verify", false, false, false, true, false},
            {"Change length byte of padding", false, false, false, false, true}
        };

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = manipulateFinishedRecordHeader((String) parameters[i][0],
                    (Boolean) parameters[i][1], (Boolean) parameters[i][2],
                    (Boolean) parameters[i][3], (Boolean) parameters[i][4],
                    (Boolean) parameters[i][5]);
        }

        return result;
    }
}
