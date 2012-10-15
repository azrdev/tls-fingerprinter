package de.rub.nds.ssl.stack.tests.fingerprint;

import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.tests.analyzer.AFingerprintAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.ssl.stack.tests.analyzer.common.ScoreCounter;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.EFingerprintIdentifier;
import de.rub.nds.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.ssl.stack.trace.MessageTrace;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

/**
 * Fingerprint the ChangeCipherSpec record header. Perform Tests by manipulating
 * the message type, protocol version and length bytes in the record header.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 06, 2012
 */
public class FingerprintCCSRecordHeader extends GenericFingerprintTest implements Observer {


    @Test(enabled = true, dataProviderClass = FingerprintDataProviders.class,
    dataProvider = "recordHeader", invocationCount = 1)
    public void manipulateCCSRecordHeader(String desc, byte[] msgType,
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
        workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        logger.info(
                EStates.CLIENT_CHANGE_CIPHER_SPEC.name() + " state is observed");

        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setProtocolVersion(protocolVersion);
        parameters.setRecordLength(recordLength);
        parameters.setIdentifier(EFingerprintIdentifier.CCSRecordHeader);
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
    public void update(final Observable o, final Object arg) {
        MessageTrace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageTrace) arg;
        }
        if (states == EStates.CLIENT_CHANGE_CIPHER_SPEC) {
            ChangeCipherSpec ccs = new ChangeCipherSpec(protocolVersion);
            byte[] payload = ccs.encode(true);
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
            trace.setCurrentRecord(ccs);
        }
    }

    /**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown() {
        workflow.closeSocket();
    }
    
    @AfterClass
    public void generateReport() {
        ScoreCounter counter = ScoreCounter.getInstance();
        int jsse = counter.getJSSEStandardScore();
        int openssl = counter.getOpenSSLScore();
        int gnutls = counter.getGNUtlsScore();
        int total = counter.getTotalCounter();
        int noHit = counter.getNoHitCounter();
        float result;
        System.out.println("JSSE Points: " + jsse);
        System.out.println("GNUtls Points: " + gnutls);
        System.out.println("OpenSSL Points: " + openssl);
        System.out.println("NoHit: " + noHit);
        //compute Probability
        result = this.computeProbability(jsse, total);
        System.out.println("Probability for JSSE: " + result);
        result = this.computeProbability(gnutls, total);
        System.out.println("Probability for GNUtls: " + result);
        result = this.computeProbability(openssl, total);
        System.out.println("Probability for OpenSSL: " + result);
        result = this.computeProbability(noHit, total);
        System.out.println("No hit in DB: " + result);

    }
    
    private float computeProbability(int impl, int total) {
        float result;
        result = ((float) impl / (float) total) * 100;
        return result;
    }
}
