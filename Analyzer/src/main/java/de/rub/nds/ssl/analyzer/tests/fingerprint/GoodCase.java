package de.rub.nds.ssl.analyzer.tests.fingerprint;

import de.rub.nds.ssl.analyzer.removeMe.SSLServerHandler;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Execute the handshake with valid parameters.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public class GoodCase extends GenericFingerprintTest implements Observer {
	/**
     * Test host.
     */
    protected final String HOST = "localhost";
    /**
     * Test port.
     */
    protected int PORT = 10443;
    /**
     * Cipher suite.
     */
    private ECipherSuite[] suite;
    /**
     * Handler to start/stop a test server.
     */
    private SSLServerHandler serverHandler = new SSLServerHandler();
    
    /**
     * Cipher suites for ClientHello.
     *
     * @return List of parameters
     */
    @DataProvider(name = "cipher")
    public Object[][] createData1() {
        return new Object[][]{
                    {new ECipherSuite[]{
                            ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA}},};
    }

    /**
     * Execute handshake.
     */
    @Test(enabled = true, dataProvider = "cipher")
    public void executeHandshake(ECipherSuite[] suite) throws SocketException {
        workflow = new TLS10HandshakeWorkflow();
        workflow.connectToTestServer(HOST, PORT);
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        this.suite = suite;
        workflow.start();
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(Observable o, Object arg) {
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_HELLO) {
            MessageBuilder builder = new MessageBuilder();
            CipherSuites suites = new CipherSuites();
            RandomValue random = new RandomValue();
            suites.setSuites(this.suite);
            ClientHello clientHello = builder.createClientHello(protocolVersion.
                    getId(),
                    random.encode(false),
                    suites.encode(false), new byte[]{0x00});
            trace.setCurrentRecord(clientHello);
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
//        System.setProperty("javax.net.debug", "ssl");
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

    @Override
    public Object call() throws Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
