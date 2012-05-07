package de.rub.nds.research.ssl.stack.tests.attacks;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.research.ssl.stack.tests.common.KeyMaterial;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.States;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Test for Vaudenay attack.
 *
 * @author Eugen Weiss -eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Mar 22, 2012
 */
public class VaudenayTest implements Observer {

    /**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private SSLTestUtils utils = new SSLTestUtils();
    /**
     * TLS protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test host.
     */
    private static final String HOST = "www.rub.de";
    /**
     * Test port.
     */
    private static final int PORT = 443;

    /**
     * Test parameters for the Vaudenay Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "vaudenay")
    public final Object[][] createData1() {
        return new Object[][]{
                    {protocolVersion, false}, //ok case
                    {protocolVersion, true} //wrong padding
                };
    }
    /**
     * Protocol version.
     */
    private EProtocolVersion pVersion;
    /**
     * Signalizes if padding should be changed.
     */
    private boolean changePadding;

    /**
     * Test Vaudenay attack.
     *
     * @param version Protocol version
     * @param changePadding True if padding should be changed
     */
    @Test(enabled = true, dataProvider = "vaudenay")
    public final void testVaudenay(EProtocolVersion version,
            boolean changePadding) {
        workflow = new SSLHandshakeWorkflow();
        workflow.connectToTestServer(HOST, PORT);
        workflow.addObserver(this, States.FINISHED);
        pVersion = version;
        this.changePadding = changePadding;
        workflow.start();

        ArrayList<Trace> traceList = workflow.getTraceList();
        ARecordFrame frame = traceList.get(traceList.size() - 1).
                getCurrentRecord();
        if (frame instanceof Alert) {
            Alert alert = (Alert) frame;
            Assert.fail("Test failed with an SSL-Alert: " + alert.getAlertLevel() + " " + alert.
                    getAlertDescription());
        }
        if ((frame instanceof TLSCiphertext) == false) {
            Assert.fail("Last message not Encrypted finished message");
        }
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public final void update(final Observable o, final Object arg) {
        Trace trace = null;
        States states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (States) obs.getState();
            trace = (Trace) arg;
        }
        switch (states) {
            case FINISHED:
                SecurityParameters param = SecurityParameters.getInstance();
                byte[] handshakeHashes = workflow.getHash();

                //create the key material
                KeyMaterial keyMat = new KeyMaterial();

                //create Finished message
                byte[] data = null;
                Finished finished = new Finished(pVersion, EConnectionEnd.CLIENT);
                try {
                    finished.createVerifyData(param.getMasterSecret(),
                            handshakeHashes);
                    data = finished.encode(true);
                } catch (InvalidKeyException e1) {
                    e1.printStackTrace();
                }

                //encrypt Finished message
                String cipherName = param.getBulkCipherAlgorithm().toString();
                String macName = param.getMacAlgorithm().toString();
                SecretKey macKey = new SecretKeySpec(keyMat.getClientMACSecret(),
                        macName);
                SecretKey symmKey = new SecretKeySpec(keyMat.getClientKey(),
                        cipherName);
                TLSCiphertext rec = new TLSCiphertext(protocolVersion,
                        EContentType.HANDSHAKE);
                GenericBlockCipher blockCipher = new GenericBlockCipher(finished);
                blockCipher.computePayloadMAC(macKey, macName);

                try {
                    byte[] payloadMAC, plaintext;
                    payloadMAC = blockCipher.getMAC();
                    plaintext = blockCipher.concatenateDataMAC(data, payloadMAC);
                    Cipher symmCipher = blockCipher.initBlockCipher(symmKey,
                            cipherName, keyMat.getClientIV());
                    byte[] paddedData, encryptedData = null;
                    int blockSize = symmCipher.getBlockSize();
                    paddedData = utils.addPadding(plaintext, blockSize,
                            this.changePadding);
                    encryptedData = symmCipher.doFinal(paddedData);
                    rec.setGenericCipher(encryptedData);
                } catch (IllegalBlockSizeException e1) {
                    e1.printStackTrace();
                } catch (BadPaddingException e1) {
                    e1.printStackTrace();
                }
                trace.setCurrentRecord(rec);
            default:
                break;

        }

    }

    /**
     * Close the Socket after the test run
     */
    @AfterMethod
    public final void tearDown() {
        try {
            workflow.getSocket().close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
