package de.rub.nds.ecctests;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * ECCExtractionTest Test - does nothing.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 14, 2012
 */
public class ECCExtractionTest implements Observer {

    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getRootLogger();
    /**
     * Handshake workflow to observe.
     */
    private TLS10HandshakeWorkflow workflow;
    /**
     * Test host.
     */
    private static final String HOST = "127.0.0.1"; //"134.147.40.41"
    /**
     * Test port.
     */
    private static final int PORT = 51707;
    /**
     * Valid point on secp256r1.
     */
    private static final byte[] VALID_PUBLIC_POINT = new byte[]{
        (byte) 0x04, (byte) 0xe6, (byte) 0xc6, (byte) 0xdf, (byte) 0x91,
        (byte) 0xd7, (byte) 0xac, (byte) 0x19, (byte) 0x0d, (byte) 0x04,
        (byte) 0x8d, (byte) 0x3c, (byte) 0x71, (byte) 0x02, (byte) 0x3f,
        (byte) 0x47, (byte) 0xbc, (byte) 0x7f, (byte) 0x58, (byte) 0xaf,
        (byte) 0xb1, (byte) 0xe2, (byte) 0x68, (byte) 0xf4, (byte) 0x7f,
        (byte) 0x4a, (byte) 0x21, (byte) 0x1a, (byte) 0x48, (byte) 0xfe,
        (byte) 0x5a, (byte) 0x31, (byte) 0xce, (byte) 0xa4, (byte) 0x64,
        (byte) 0x90, (byte) 0x6a, (byte) 0x75, (byte) 0x72, (byte) 0x46,
        (byte) 0x39, (byte) 0xca, (byte) 0x8b, (byte) 0xec, (byte) 0x68,
        (byte) 0x4c, (byte) 0x65, (byte) 0xbb, (byte) 0x00, (byte) 0x10,
        (byte) 0x5c, (byte) 0x9d, (byte) 0xb4, (byte) 0xe7, (byte) 0xa9,
        (byte) 0x29, (byte) 0xba, (byte) 0xfd, (byte) 0x2f, (byte) 0x6c,
        (byte) 0x0a, (byte) 0xe0, (byte) 0x99, (byte) 0x51, (byte) 0xd6
    };
    /**
     * Nasty point on secp256r1.
     */
    private static final byte[] NASTY_PUBLIC_POINT = new byte[]{
        (byte) 0x04, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xab, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xa9
    };
    private static final byte[] VALID_PUBLIC_POINT_2 = new byte[]{
        (byte) 0x04, (byte) 0x85, (byte) 0x62, (byte) 0xb1, (byte) 0xb7,
        (byte) 0x0d, (byte) 0x5a, (byte) 0xfe, (byte) 0x4e, (byte) 0xef,
        (byte) 0xd1, (byte) 0xe1, (byte) 0x0c, (byte) 0xea, (byte) 0x0f,
        (byte) 0xcb, (byte) 0x7a, (byte) 0x93, (byte) 0x57, (byte) 0x5a,
        (byte) 0x19, (byte) 0x57, (byte) 0x4e, (byte) 0x70, (byte) 0x91,
        (byte) 0x97, (byte) 0xef, (byte) 0x9e, (byte) 0x30, (byte) 0xae,
        (byte) 0x9d, (byte) 0xf3, (byte) 0xf1, (byte) 0x98, (byte) 0x96,
        (byte) 0x8a, (byte) 0xd8, (byte) 0x9e, (byte) 0xe1, (byte) 0x99,
        (byte) 0x96, (byte) 0xe3, (byte) 0x6a, (byte) 0xb9, (byte) 0x20,
        (byte) 0xc7, (byte) 0xd9, (byte) 0xa2, (byte) 0x69, (byte) 0x91,
        (byte) 0xa4, (byte) 0x1e, (byte) 0xb1, (byte) 0xb5, (byte) 0x01,
        (byte) 0xa8, (byte) 0x1a, (byte) 0xe3, (byte) 0xb8, (byte) 0x78,
        (byte) 0xc9, (byte) 0x6f, (byte) 0xa7, (byte) 0xcb, (byte) 0xdd
    };
    private static final byte[] NASTY_PUBLIC_POINT_2 = new byte[]{
        (byte) 0x04, (byte) 0xab, (byte) 0x88, (byte) 0xac, (byte) 0x8f,
        (byte) 0x5e, (byte) 0xa4, (byte) 0xe5, (byte) 0x33, (byte) 0xee,
        (byte) 0x27, (byte) 0x1e, (byte) 0xda, (byte) 0xf4, (byte) 0x3f,
        (byte) 0xc2, (byte) 0xe3, (byte) 0x26, (byte) 0x0c, (byte) 0xf0,
        (byte) 0xce, (byte) 0x96, (byte) 0x88, (byte) 0x70, (byte) 0x19,
        (byte) 0xd0, (byte) 0x6e, (byte) 0xb2, (byte) 0x0e, (byte) 0x1d,
        (byte) 0xe0, (byte) 0x10, (byte) 0x62, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    @BeforeClass
    public void setUp() {
        // code that will be invoked before this test starts
    }

    @Test(enabled = true)
    public final void testECCExtension() throws SocketException {
        logger.info("++++ Start Test No. 1 (ECC Extension test) ++++");
//        Security.addProvider(new SunEC());
//        for (Provider provider : Security.getProviders()) {
//            System.out.println(provider);
//        }

        workflow = new TLS10HandshakeWorkflow(false);
        workflow.connectToTestServer(HOST, PORT);
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);

        //start workflow
        workflow.start();
        logger.info("------------------------------");
    }

    @AfterClass
    public void cleanUp() {
        // code that will be invoked after this test ends
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
        TLS10HandshakeWorkflow.EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    ClientHello clientHello =
                            (ClientHello) trace.getCurrentRecord();

                    CipherSuites suites = new CipherSuites();
                    suites.setSuites(new ECipherSuite[]{
                        ECipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
                    });
                    clientHello.setCipherSuites(suites);

                    Extensions extensions = new Extensions();
                    EllipticCurves curves = new EllipticCurves();
                    curves.setSupportedCurves(new ENamedCurve[]{
                        ENamedCurve.SECP_256_R1, 
                    //                        ENamedCurve.SECP_384_R1,
                    //                        ENamedCurve.SECP_521_R1
                    });
                    extensions.addExtension(curves);
                    SupportedPointFormats formats = new SupportedPointFormats();
                    formats.setSupportedPointFormats(new EECPointFormat[]{
                        EECPointFormat.UNCOMPRESSED
                    });
                    extensions.addExtension(formats);
                    clientHello.setExtensions(extensions);

                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    ClientKeyExchange cke = new ClientKeyExchange(
                            EProtocolVersion.TLS_1_0,
                            EKeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
                    byte[] tmp = VALID_PUBLIC_POINT_2;
//                    byte[] tmp = NASTY_PUBLIC_POINT_2;
                    // destroy the point
                    tmp[tmp.length - 6] = 17;                 

                    ClientECDHPublic keyMaterial = new ClientECDHPublic();
                    ECPoint newPoint = new ECPoint();
                    newPoint.setPoint(tmp);
                    keyMaterial.setECDHYc(newPoint);
                    keyMaterial.setExplicitPublicValueEncoding(true);
                    cke.setExchangeKeys(keyMaterial);

                    trace.setCurrentRecord(cke);
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
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
        //serverHandler.shutdownTestServer();
    }
}
