package de.rub.nds.ssl.analyzer.tests.fingerprint;

import de.rub.nds.ssl.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.analyzer.removeMe.TestConfiguration;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.analyzer.tests.parameters.ClientKeyExchangeParams;
import de.rub.nds.ssl.analyzer.tests.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class FingerprintClientKeyExchange extends GenericFingerprintTest
        implements Observer {

    /**
     * Test port.
     */
    protected int PORT = 443;
    /**
     * Test parameters.
     */
    private ClientKeyExchangeParams parameters = new ClientKeyExchangeParams();

    /**
     * Test parameters for ClientKeyExchange fingerprinting.
     *
     * @return List of parameters
     */
    @DataProvider(name = "clientKeyExchange")
    public Object[][] createData1() {
        return new Object[][]{
                    {"Invalid payload for RSA key exchange", new ECipherSuite[]{
                            ECipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
                        new byte[]{(byte) 0x00, (byte) 0x00}}
                };
    }

    /**
     * Start SSL handshake.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    @Test(enabled = true, dataProvider = "clientKeyExchange")
    public void fingerprintClientKeyExchange(String desc,
            ECipherSuite[] cipherSuite, byte[] payload) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.
                    info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_FINISHED.name() + " state is observed");

        //set the test parameters
        parameters.setCipherSuite(cipherSuite);
        parameters.setPayload(payload);
        parameters.setIdentifier(EFingerprintIdentifier.ClientKeyExchange);
        parameters.setDescription(desc);

        //start the handshake
        workflow.start();

        //analyze the handshake trace
        AFingerprintAnalyzer analyzer = new TestHashAnalyzer(parameters);
        analyzer.analyze(workflow.getTraceList());

        this.counter++;
        logger.info("++++Test finished.++++");
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(Observable o, Object arg) {
        MessageBuilder msgBuilder = new MessageBuilder();
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(parameters.getCipherSuite());
                    ClientHello clientHello = msgBuilder.
                            createClientHello(EProtocolVersion.TLS_1_0.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    ClientKeyExchange cke = msgBuilder.createClientKeyExchange(
                            protocolVersion, this.workflow);
                    ClientDHPublic clientDHPublic = new ClientDHPublic();
                    clientDHPublic.setDhyc(parameters.getPayload());
                    cke.setExchangeKeys(clientDHPublic);
                    //update the trace object
                    trace.setCurrentRecord(cke);
                default:
                    break;
            }
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
    }
}
