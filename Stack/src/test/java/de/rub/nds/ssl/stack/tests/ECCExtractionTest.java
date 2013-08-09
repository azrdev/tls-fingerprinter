package de.rub.nds.ssl.stack.tests;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
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
    private static final String HOST = "127.0.0.1";
    /**
     * Test port.
     */
    private static final int PORT = 53101;
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
        (byte) 0x04, (byte) 0x48, (byte) 0xc2, (byte) 0xea, (byte) 0x5c,
        (byte) 0x39, (byte) 0xde, (byte) 0xa6, (byte) 0x6f, (byte) 0x48,
        (byte) 0x0a, (byte) 0x97, (byte) 0xd3, (byte) 0x5b, (byte) 0xff,
        (byte) 0x72, (byte) 0xc4, (byte) 0x9e, (byte) 0xd4, (byte) 0x53,
        (byte) 0x46, (byte) 0x8a, (byte) 0x6b, (byte) 0x59, (byte) 0x12,
        (byte) 0x3a, (byte) 0x6d, (byte) 0x88, (byte) 0xa8, (byte) 0x81,
        (byte) 0x9b, (byte) 0x97, (byte) 0xb0, (byte) 0x8e, (byte) 0x47,
        (byte) 0xa2, (byte) 0x60, (byte) 0x9f, (byte) 0x0b, (byte) 0xde,
        (byte) 0x66, (byte) 0xff, (byte) 0x6a, (byte) 0x3c, (byte) 0xaa,
        (byte) 0x3f, (byte) 0x87, (byte) 0x31, (byte) 0xd9, (byte) 0xfe,
        (byte) 0xfa, (byte) 0xc1, (byte) 0xa4, (byte) 0xbe, (byte) 0x53,
        (byte) 0x64, (byte) 0x52, (byte) 0x5a, (byte) 0x9a, (byte) 0x4c,
        (byte) 0x65, (byte) 0x45, (byte) 0xf4, (byte) 0x03, (byte) 0xd4
    };

    @BeforeClass
    public void setUp() {
        // code that will be invoked before this test starts
    }

    @Test(enabled = true)
    public final void testECCExtension() throws SocketException {
        logger.info("++++ Start Test No. 1 (ECC Extension test) ++++");
        workflow = new TLS10HandshakeWorkflow();
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
                        ECipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA});
                    clientHello.setCipherSuites(suites);

                    Extensions extensions = new Extensions();
                    EllipticCurves curves = new EllipticCurves();
                    curves.setSupportedCurves(new ENamedCurve[]{
                        ENamedCurve.SECP_256_R1
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
                    ClientKeyExchange cke =
                            (ClientKeyExchange) trace.getCurrentRecord();
//                    byte[] tmp = VALID_PUBLIC_POINT;
                    byte[] tmp = NASTY_PUBLIC_POINT;
                    // destroy the point
//                    tmp[tmp.length - 6] = 17;                 

                    ClientECDHPublic keyMaterial = new ClientECDHPublic();
                    ECPoint newPoint = new ECPoint();
                    newPoint.setPoint(tmp);
                    keyMaterial.setECDHYc(newPoint);
                    keyMaterial.setExplicitPublicValueEncoding(true);
                    cke.setExchangeKeys(keyMaterial);
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
