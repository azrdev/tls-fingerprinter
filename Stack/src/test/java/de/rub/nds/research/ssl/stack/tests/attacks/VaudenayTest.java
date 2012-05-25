package de.rub.nds.research.ssl.stack.tests.attacks;

import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.TraceListAnalyzer;
import de.rub.nds.research.ssl.stack.tests.common.KeyMaterial;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.common.SSLServer;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.testng.Reporter;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
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
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Test Server Thread.
     */
    private Thread sslServerThread;
    /**
     * Test SSL Server.
     */
    private SSLServer sslServer;
    /**
     * Server key store.
     */
    private static final String PATH_TO_JKS = "server.jks";
    /**
     * Pass word for server key store.
     */
    private static final String JKS_PASSWORD = "server";
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;

    /**
     * Test parameters for the Vaudenay Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "vaudenay")
    public final Object[][] createData1() {
        return new Object[][]{
                    {"OK case", protocolVersion, false},
                    {"Wrong padding", protocolVersion, true}
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
    public final void testVaudenay(String desc,
            EProtocolVersion version, boolean changePadding) {
        workflow = new SSLHandshakeWorkflow();
        workflow.connectToTestServer(HOST, PORT);
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        pVersion = version;
        this.changePadding = changePadding;
        workflow.start();

        Reporter.log("Test No." + this.counter + " : " + desc);
        TraceListAnalyzer analyze = new TraceListAnalyzer();
        analyze.logOutput(workflow.getTraceList());
        Reporter.log("------------------------------");
        this.counter++;
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
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_FINISHED:
                    SecurityParameters param = SecurityParameters.getInstance();
                    byte[] handshakeHashes = workflow.getHash();

                    //create the key material
                    KeyMaterial keyMat = new KeyMaterial();

                    //create Finished message
                    byte[] data = null;
                    Finished finished = new Finished(pVersion,
                            EConnectionEnd.CLIENT);
                    if (param.getMasterSecret() != null
                            && handshakeHashes != null) {
                        try {
                            finished.createVerifyData(param.getMasterSecret(),
                                    handshakeHashes);
                            data = finished.encode(true);
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
                            plaintext = blockCipher.concatenateDataMAC(data,
                                    payloadMAC);
                            Cipher symmCipher = blockCipher.initBlockCipher(
                                    symmKey,
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
                    }
                    trace.setCurrentRecord(rec);
                default:
                    break;

            }
        }
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
        try {
//            System.setProperty("javax.net.debug", "ssl");
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        try {
            workflow.closeSocket();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            if (sslServer != null) {
                sslServer.shutdown();
                sslServer = null;
            }

            if (sslServerThread != null) {
                sslServerThread.interrupt();
                sslServerThread = null;
            }


            Thread.currentThread().sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
