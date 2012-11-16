package de.rub.nds.ssl.stack.tests.attacktests;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.*;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.FinishedParameters;
import de.rub.nds.ssl.stack.tests.common.SSLServerHandler;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.KeyMaterial;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
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
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.*;

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
    private TLS10HandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private MessageUtils utils = new MessageUtils();
    /**
     * TLS protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
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
     * Handler to start/stop a test server.
     */
    private SSLServerHandler serverHandler = new SSLServerHandler();
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Test parameters for finished message.
     */
    private FinishedParameters parameters = new FinishedParameters();

    /**
     * Test parameters for the Vaudenay Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "vaudenay")
    public final Object[][] createData() {
        return new Object[][]{
                    {"OK case", false, false, false, false, false},
                    {"Wrong padding", true, false, false, false, false},
                    {"Destroy MAC", false, true, false, false, false},
                    {"Destroy hash value", false, false, true, false, false},
                    {"Destroy Verify", false, false, false, true, false},
                    {"Change length byte of padding", false, false, false,
                        false, true}
                };
    }

    /**
     * Test Vaudenay attack.
     *
     * @param version Protocol version
     * @param changeByteArray True if padding should be changed
     * @throws SocketException
     */
    @Test(enabled = true, dataProvider = "vaudenay")
    public final void testVaudenay(String desc, boolean changePadding,
            boolean destroyMAC,
            boolean destroyHash, boolean destroyVerify, boolean changePadLength)
            throws SocketException {
        logger.info("++++ Start Test No." + this.counter + " (" + desc + ") ++++");
        workflow = new TLS10HandshakeWorkflow();
        workflow.connectToTestServer(HOST, PORT);
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_FINISHED);
        //set parameters
        parameters.setChangePadding(changePadding);
        parameters.setChangePadLength(changePadLength);
        parameters.setDestroyHash(destroyHash);
        parameters.setDestroyVerify(destroyVerify);
        parameters.setDestroyMAC(destroyMAC);
        //start workflow
        workflow.start();
        logger.info("------------------------------");
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
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    MessageBuilder builder = new MessageBuilder();
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA});
                    ClientHello clientHello =
                            builder.createClientHello(EProtocolVersion.TLS_1_0.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_FINISHED:
                    SecurityParameters param = SecurityParameters.getInstance();
                    byte[] handshakeHashes = workflow.getHash();
                    if (parameters.isDestroyHash()) {
                        handshakeHashes[5] = (byte) 0x00;
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
                            if (parameters.isDestroyVerify()) {
                                byte[] tmp = finished.getVerifyData();
                                tmp[8] = 0x00;
                                finished.setVerifyData(tmp);
                            }
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
                            if (parameters.isDestroyMAC()) {
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
                                    parameters.isChangePadding());
                            if (parameters.isChangePadLength()) {
                                paddedData[paddedData.length - 1] = 0x00;
                                logger.debug("Padded data: " + Utility.
                                        bytesToHex(paddedData));
                            }
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
     * Initialize logging properties
     */
    @BeforeClass
    public void setUpClass() {
        PropertyConfigurator.configure("logging.properties");
        logger.info("##################################");
        logger.info(this.getClass().getSimpleName());
        logger.info("##################################");
    }

    /**
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
//        System.setProperty("javax.net.debug", "all");
        serverHandler.startTestServer();
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
        serverHandler.shutdownTestServer();
    }
}
