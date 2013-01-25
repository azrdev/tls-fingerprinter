package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
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

public final class FINHandshakeHeader extends AGenericFingerprintTest
        implements Observer {

    private ResultWrapper manipulateFinishedHandshakeHeader(final String desc,
            final byte[] msgType, final byte[] recordLength)
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
        headerParameters.setMsgType(msgType);
        headerParameters.setRecordLength(recordLength);
        headerParameters.
                setIdentifier(EFingerprintTests.FIN_HH);
        headerParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(headerParameters, workflow.getTraceList(),
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
            if (headerParameters.getMsgType() != null) {
                byte[] msgType = headerParameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 0, msgType.length);
            }
            //change record length of the message
            if (headerParameters.getRecordLength() != null) {
                byte[] recordLength = headerParameters.getRecordLength();
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
                    logger.error("Wrong blocksize.", e1);
                } catch (BadPaddingException e1) {
                    logger.error("Invalid padding.", e1);
                }
            }
            byte[] encrypted = rec.encode(true);
            //update the trace object
            trace.setCurrentRecordBytes(encrypted);
            trace.setCurrentRecord(rec);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Wrong message type", new byte[]{(byte) 0xff}, null},
            {"Invalid length 0x00,0x00,0x00", null,
                new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}},
            {"Invalid length 0xff,0xff,0xff", null,
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff}}};

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = manipulateFinishedHandshakeHeader(
                    (String) parameters[i][0], (byte[]) parameters[i][1],
                    (byte[]) parameters[i][2]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
