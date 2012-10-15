package de.rub.nds.ssl.stack.tests.fingerprint;

import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.trace.MessageTrace;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;

/**
 * Fingerprint the ClientHello record header. Perform Tests by manipulating the
 * message type, protocol version and length bytes in the record header.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 30, 2012
 */
public class FingerprintCHRecordHeader extends GenericFingerprintTest implements Observer {
    /**
     * Test port.
     */
    protected int PORT = 443;

    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "recordHeader", invocationCount = 1)
    public void manipulateCHRecordHeader(String desc, byte[] msgType,
            byte[] protocolVersion, byte[] recordLength) throws SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
            workflow.connectToTestServer(HOST, PORT);
            logger.info("Test Server: " + HOST + ":" + PORT);
        } else {
            workflow.connectToTestServer(TestConfiguration.HOST,
                    TestConfiguration.PORT);
            logger.info(
                    "Test Server: " + TestConfiguration.HOST + ":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");

        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setProtocolVersion(protocolVersion);
        parameters.setRecordLength(recordLength);
        parameters.setIdentifier(EFingerprintIdentifier.CHRecordHeader);
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
        MessageTrace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageTrace) arg;
        }
        if (states == EStates.CLIENT_HELLO) {
            ECipherSuite[] suites = new ECipherSuite[]{
                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
            CipherSuites cipherSuites = new CipherSuites();
            cipherSuites.setSuites(suites);
            RandomValue random = new RandomValue();
            byte[] compMethod = new byte[]{0x00};
            //create ClientHello message
            ClientHello clientHello = msgBuilder.createClientHello(this.protocolVersion.
                    getId(),
                    random.encode(false), cipherSuites.encode(false), compMethod);
            byte[] payload = clientHello.encode(true);
            //change msgType of the message
            if (parameters.getMsgType() != null) {
                byte[] msgType = parameters.getMsgType();
                System.arraycopy(msgType, 0, payload, 0, msgType.length);
            }
            //change record length of the message
            if (parameters.getRecordLength() != null) {
                byte[] recordLength = parameters.getRecordLength();
                System.arraycopy(recordLength, 0, payload, 3,
                        recordLength.length);
            }
            //change protocol version of the message
            if (parameters.getProtocolVersion() != null) {
                byte[] protVersion = parameters.getProtocolVersion();
                System.arraycopy(protVersion, 0, payload, 1, protVersion.length);
            }
            //update the trace object
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(clientHello);
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
