package de.rub.nds.ssl.stack.tests;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import java.util.List;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Dummy Test - does nothing.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 14, 2012
 */
public class Dummy implements Observer {
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
    private static final String HOST = "www.google.de";
    /**
     * Test port.
     */
    private static final int PORT = 443;
    
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
                    Extensions extensions = new Extensions();
                    CipherSuites suites = new CipherSuites();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA});
                    ClientHello clientHello = 
                            (ClientHello) trace.getCurrentRecord();
                    /*
                    extensions.setExtensions(new EExtensionType[]{
                        EExtensionType.EC_POINT_FORMATS, 
                        EExtensionType.ELLIPTIC_CURVES
                    });*/
                    
                    //clientHello.setExtensions(extensions);
                    trace.setCurrentRecord(clientHello);
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
