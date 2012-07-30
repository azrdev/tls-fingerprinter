package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLServerHandler;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import java.net.SocketException;

/**
 * Execute the handshake with valid parameters.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 30, 2012
 */
public class TestGoodCase extends GenericFingerprintTest implements Observer {
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
        workflow = new SSLHandshakeWorkflow();
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
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
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
     * Start the target SSL Server.
     */
    @BeforeMethod
    public void setUp() {
        System.setProperty("javax.net.debug", "ssl");
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
