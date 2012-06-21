package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.tests.analyzer.HeaderParameters;
import de.rub.nds.research.ssl.stack.tests.analyzer.TestHashAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.common.TestConfiguration;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;

/**
 * Fingerprint the ChangeCipherSpec record header. Perform Tests by
 * manipulating the message type, protocol version and length
 * bytes in the record header.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 06, 2012
 */
public class FingerprintCCSRecordHeader implements Observer {
	
	/**
     * Handshake workflow to observe.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 443;
    /**
     * Test counter.
     */
    private int counter = 1;
    /**
     * Default protocol version.
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    
    /**
     * Test parameters.
     */
    private HeaderParameters parameters = new HeaderParameters();
    
    /**
     * Log4j logger initialization.
     */
    static Logger logger = Logger.getRootLogger();
    
    /**
     * Load the logging properties.
     */
    @BeforeClass
    public void setUp() {
    	PropertyConfigurator.configure("logging.properties");
    }
    
    
    @Test(enabled = true, dataProviderClass=FingerprintDataProviders.class,
    		dataProvider = "recordHeader", invocationCount = 1)
    public void manipulateCCSRecordHeader(String desc, byte [] msgType,
    		byte [] protocolVersion, byte [] recordLength) {
    	logger.info("++++Start Test No." + counter + "(" + desc +")++++");
        workflow = new SSLHandshakeWorkflow();
        //connect to test server
        if (TestConfiguration.HOST.isEmpty() || TestConfiguration.PORT == 0) {
        	workflow.connectToTestServer(HOST, PORT);
        	logger.info("Test Server: " + HOST +":" +PORT);
        }
        else {
        	workflow.connectToTestServer(TestConfiguration.HOST,
        			TestConfiguration.PORT);
        	logger.info("Test Server: " + TestConfiguration.HOST +":" + TestConfiguration.PORT);
        }
        //add the observer
        workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
        logger.info(EStates.CLIENT_CHANGE_CIPHER_SPEC.name() + " state is observed");
        
        //set the test parameters
        parameters.setMsgType(msgType);
        parameters.setProtocolVersion(protocolVersion);
        parameters.setRecordLength(recordLength);
        parameters.setTestClassName(this.getClass().getName());
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
        Trace trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (Trace) arg;
        }
        if (states == EStates.CLIENT_CHANGE_CIPHER_SPEC) {
        	ChangeCipherSpec ccs = new ChangeCipherSpec(protocolVersion);
        	byte [] payload = ccs.encode(true);
            //change msgType of the message
            if (parameters.getMsgType() != null) {
            	byte [] msgType = parameters.getMsgType();
            	System.arraycopy(msgType, 0, payload, 0, msgType.length);
            }
            //change record length of the message
            if (parameters.getRecordLength() != null) {
            	byte [] recordLength = parameters.getRecordLength();
            	System.arraycopy(recordLength, 0, payload, 3, recordLength.length);
            }
            //change protocol version of the message
            if (parameters.getProtocolVersion() != null) {
            	byte [] protVersion = parameters.getProtocolVersion();
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
}
