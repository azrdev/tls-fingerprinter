package de.rub.nds.ssl.analyzer.tests.attack;

import de.rub.nds.ssl.analyzer.removeMe.SSLServer;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import static java.lang.Thread.sleep;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import javax.crypto.BadPaddingException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import sun.security.rsa.RSACore;

/**
 * Test for Bleichenbacher attack.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.2 Apr 12, 2012
 */
public class BleichenbacherTiming implements Observer {

    /**
     * Client hello message.
     */
    private ClientHello clientHello;
    /**
     * Handshake workflow to observe.
     */
    private TLS10HandshakeWorkflow workflow;
    /**
     * Help utilities for testing.
     */
    private MessageUtils utils = new MessageUtils();
    /**
     * TLS protocol version of the record frame.
     */
    private EProtocolVersion protocolVersionRecord = EProtocolVersion.TLS_1_0;
    /**
     * TLS protocol version of the premaster secret.
     */
    private EProtocolVersion protocolVersionPMS = EProtocolVersion.TLS_1_0;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Test host.
     */
    private static final String HOST = "127.0.0.1";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Separate byte between padding and data in PKCS#1 message.
     */
    private byte[] separateByte;
    /**
     * First two bytes of PKCS#1 message which defines the op-mode.
     */
    private byte[] pkcsMode;
    /**
     * Signalizes if padding should be changed.
     */
    private boolean chgPadding;
    /**
     * Position in padding to change.
     */
    private MessageUtils.POSITIONS positionOfPaddingChange;
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
     * Overall delays.
     */
    private final long[] delays = new long[NUMBER_OF_REPETIIONS];
    /**
     * Number of repetitions.
     */
    private static final int NUMBER_OF_REPETIIONS = 1000;
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = false;
    /*
     * Flags if MAC should be invalidated
     */
    private boolean destroyMAC = false;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Test counter.
     */
    private int counter = 1;
    private int timingCounter = 1;
    
    /**
     * Enable debug logging for SSL server
     */
    private boolean debug = false;
       
    /**
     * Test parameters for the Bleichenbacher Tests.
     *
     * @return List of parameters
     */
    @DataProvider(name = "bleichenbacher")
    public Object[][] createData1() {
        // System.setProperty("javax.net.debug", "all");
        setUp();
        if(new File("delays.csv").delete()) {
            logger.info("delays.csv deleted");
        } else {
            logger.info("delays.csv not found");
        }
        Object[][] ret = new Object[NUMBER_OF_REPETIIONS][];
        
        for(int i = 0; i < ret.length; i++) {
            Object temp[];
            
            switch(i % 2) {
                case 0:
                    temp = new Object[] {
                            new byte[]{0x09, 0x02},
                            new byte[]{0x00},
                            protocolVersionRecord,
                            false,
                            MessageUtils.POSITIONS.FIRST,
                            "fa1",
                            false
                    };
                    break;
                    
                case 1:
                    temp = new Object[] {
                            new byte[]{0x00, 0x02},
                            new byte[]{0x00},
                            protocolVersionRecord,
                            false,
                            MessageUtils.POSITIONS.FIRST,
                            "ok1",
                            false
                    };
                    break;

                default:
                    temp = null;
                    logger.error("This should never happen");
                    return null;
            }
            ret[i] = temp;
            
        }
        return ret;
        /* {
                    // failure case
                    {new byte[]{0x09, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST, "Ignore",
                        false},
                    // failure case
                    {new byte[]{0x09, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST, "FAILED",
                        false},
                    // ok case
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST, "OK",
                        false},
                    // failure case
                    {new byte[]{0x09, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST, "FAILED",
                        false},
                    // ok case
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST, "OK",
                        false}
                    
                
                   // wrong protocol version in PreMasterSecret
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Wrong protocol version in PreMasterSecret",
                        false},
                    // seperate byte is not 0x00
                    {new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Seperate byte is not 0x00",
                        false},
                    // mode changed
                    {new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Mode changed to 0x01",
                        false},
                    // zero byte at the first position of the padding
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.FIRST,
                        "Zero byte at the first position of the padding",
                        false},
                    // zero byte in the middle of the padding string
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.MIDDLE,
                        "Zero byte in the middle of the padding string",
                        false},
                    // zero byte at the end of the padding string
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.LAST,
                        "Zero byte at the end of the padding string",
                        false},
                    // ok case, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST,
                        "MSG ok, MAC tampered",
                        true},
                    // wrong protocol version in PreMasterSecret, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        EProtocolVersion.SSL_3_0, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Wrong protocol version in PreMasterSecret, "
                        + "MAC tampered", true},
                    // seperate byte is not 0x00
                    {new byte[]{0x00, 0x02}, new byte[]{0x01},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Seperate byte is not 0x00, MAC tampered",
                        true},
                    // mode changed, MAC tampered
                    {new byte[]{0x00, 0x01}, new byte[]{0x00},
                        protocolVersionRecord, false,
                        MessageUtils.POSITIONS.FIRST,
                        "Mode changed to 0x01, MAC tampered",
                        true},
                    // zero byte at the first position of the padding, 
                    // MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.FIRST,
                        "Zero byte at the first position of the padding, "
                        + "MAC tampered", true},
                    // zero byte in the middle of the padding string, 
                    // MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.MIDDLE,
                        "Zero byte in the middle of the padding string, "
                        + "MAC tampered", true},
                    // zero byte at the end of the padding string, MAC tampered
                    {new byte[]{0x00, 0x02}, new byte[]{0x00},
                        protocolVersionRecord, true,
                        MessageUtils.POSITIONS.LAST,
                        "Zero byte at the end of the padding string, "
                        + "MAC tampered", true}
                };*/
        
    }

    /**
     * Test if Bleichenbacher attack is possible.
     *
     * @param mode First two bytes of PKCS#1 message which defines the op-mode
     * @param separate Separate byte between padding and data in PKCS#1 message
     * @param version Protocol version
     * @param changeByteArray True if padding should be changed
     * @param position Position where padding is changed
     * @param desc Test description
     * @param tamperMAC Destroy Finished MAC of RecordFrame
     */
    @Test(enabled = false, dataProvider = "bleichenbacher")
    public final void testBleichenbacherPossible(final byte[] mode,
            final byte[] separate, final EProtocolVersion version,
            final boolean changePadding, final MessageUtils.POSITIONS position,
            final String desc, boolean tamperMAC) {
        logger.setLevel(Level.INFO);
        this.pkcsMode = mode.clone();
        this.separateByte = separate.clone();
        this.protocolVersionPMS = version;
        this.chgPadding = changePadding;
        this.positionOfPaddingChange = position;
        this.destroyMAC = tamperMAC;
        boolean canceled = false;
        
        logger.info("\n++++ Start Test No." + counter + " (" + desc + ") ++++");
        System.out.print(desc + ";");
        try {
            workflow = new TLS10HandshakeWorkflow(ESupportedSockets.TimingSocket);
            // workflow = new TLS10HandshakeWorkflow(ESupportedSockets.StandardSocket);
            workflow.connectToTestServer(HOST, PORT);
            workflow.addObserver(this, EStates.CLIENT_HELLO);
            workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
            workflow.addObserver(this, EStates.CLIENT_FINISHED);
            workflow.start();

            delays[0] = analyzeTrace(workflow.getTraceList());
            workflow.closeSocket();
        } catch (Exception e) {
            logger.error("################## custom failed");
            e.printStackTrace();
        }
        try {
            // logger.info("Writing timings to file");
            FileWriter fw = new FileWriter("delays.csv", true);
            fw.write(timingCounter + ";" + desc + ";" + delays[0] + "\n");
            timingCounter += 1;
            fw.close();
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(BleichenbacherTiming.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

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
        EStates states = null;
        MessageContainer trace = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
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
                                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                    clientHello = builder.createClientHello(
                            EProtocolVersion.TLS_1_0.getId(), random.encode(
                            false),
                            suites.encode(false), new byte[]{0x00});

                    trace.setCurrentRecord(clientHello);
                    
                    
                    break;
                case CLIENT_KEY_EXCHANGE:
                    
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            protocolVersionRecord,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms =
                            new PreMasterSecret(protocolVersionPMS);
                    workflow.setPreMasterSecret(pms);
                    pms.setProtocolVersion(this.protocolVersionPMS);
                    byte[] encodedPMS = pms.encode(false);

                    //encrypt the PreMasterSecret
                    EncPreMasterSecret encPMS =
                            new EncPreMasterSecret(pk);
                    BigInteger mod = null;
                    RSAPublicKey rsaPK = null;
                    if (pk != null && pk instanceof RSAPublicKey) {
                        rsaPK = (RSAPublicKey) pk;
                        mod = rsaPK.getModulus();
                    }

                    int modLength = 0;
                    if (mod != null) {
                        modLength = mod.bitLength() / 8;
                    }
                    /*
                     * set the padding length of the PKCS#1 padding string (it
                     * is [<Modulus length> - <Data length> -3])
                     */
                    utils.setPaddingLength((modLength - encodedPMS.length - 3));
                    utils.setSeparateByte(this.separateByte);
                    utils.setMode(this.pkcsMode);
                    //generate the PKCS#1 padding string
                    byte[] padding = utils.createPaddingString(utils.
                            getPaddingLength());
                    if (this.chgPadding) {
                        padding = utils.changeByteArray(padding,
                                this.positionOfPaddingChange, (byte) 0x00);
                        utils.setPadding(padding);
                    }

                    //put the PKCS#1 pieces together
                    byte[] clear = utils.buildPKCS1Msg(encodedPMS);

                    //compute c = m^e mod n (RSA encryption)
                    byte[] ciphertext = null;
                    try {
                        ciphertext = RSACore.rsa(clear, rsaPK);
                        encPMS.setEncryptedPreMasterSecret(ciphertext);
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }
                    
                    cke.setExchangeKeys(encPMS);
                    trace.setCurrentRecord(cke);
                    break;
                case CLIENT_FINISHED:
                    if (destroyMAC) {
                        ARecordFrame finished = trace.getCurrentRecord();
                        byte[] payload = finished.encode(true);
                        // frag the mac
//                        payload[24] = 1;
                        trace.setCurrentRecordBytes(payload);
                    }
                    break;
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
     * Close the Socket after the test run.
     */
    @AfterClass
    public final void tearDown() {
        try {
            if (sslServer != null) {
                sslServer.shutdown();
                sslServer = null;
            }

            if (sslServerThread != null) {
                sslServerThread.interrupt();
                sslServerThread = null;
            }

            Thread.interrupted();
            sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Start the target SSL Server.
     */
    //@BeforeMethod
    public final void setUp() {
        try {
            if(debug) {
                System.setProperty("javax.net.debug", "ssl");
            }
            logger.info("Starting SSL Server");
            sslServer = new SSLServer(PATH_TO_JKS, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Analyzes a given MessageContainer list and computes timing delay.
     *
     * @param traces MessageContainer list
     * @return Timing delay.
     */
    private static long analyzeTrace(final List<MessageContainer> traces) {
        
        for (MessageContainer trace : traces) {
            if (trace.getState() != null) {
                Long timestamp = trace.getTimestamp();
                
                if(timestamp > 0) {
                    return timestamp;
                }
            } else {
                logger.error("race.getState() == null");
            }
        }
        logger.error("Did not receive the expected states in the trace.");
        for (MessageContainer trace : traces) {
             logger.error("--> " + trace.getState());
        }
         
        return -1;
    }
}
