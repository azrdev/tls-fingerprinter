package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Observable;
import java.util.Observer;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.tests.analyzer.TraceListAnalyzer;
import de.rub.nds.research.ssl.stack.tests.common.MessageBuilder;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;

/**
 * Fingerprint the ClientHello SSL message.
 * @author Eugen Weiss -eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Apr 18, 2012
 */
public class FingerprintClientHello implements Observer {

	/**Handshake workflow to observe.*/
	private SSLHandshakeWorkflow workflow;
	/**Help utilities for testing.*/
	private SSLTestUtils utils = new SSLTestUtils();
	/**Patterns to create suite batch.*/
	private String [] patterns1 = {"TLS_DHE_DSS","TLS_DH_DSS"};
	private String [] patterns2 = {"TLS_DH_anon"};
	private String [] patterns3 = {"TLS"};
	/**Test host.*/
    private static final String HOST = "localhost";
    /**Test port.*/
    private static final int PORT = 443;
    /**
     * Test counter.
     */
    private int counter = 1;
	
	/**Test parameters.*/
	private byte [] protVersion;
	private byte [] random;
	private byte [] cipherSuites;
	private byte [] compMethod;
	
	/**Test constants*/
	private final ECipherSuite[] suites1 = new ECipherSuite[]{ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
	private final ECipherSuite[] suites2 = utils.constructSuiteBatch(patterns1);
	private final ECipherSuite[] suites3 = utils.constructSuiteBatch(patterns2);
	private final ECipherSuite[] suites4 = new ECipherSuite[]{};
	private final ECipherSuite[] suites5 = utils.constructSuiteBatch(patterns3);
	
	/** Test parameters for ClientHello fingerprinting.
	 * @return List of parameters
	 */
    @DataProvider(name = "clientHello")
    public Object[][] createData1() {
    	//byte [] random1 = new byte[]{0x00,0x00,0x00,0x00,0x00};
    	RandomValue random2 = new RandomValue();
        return new Object[][]{
				{"OK case",EProtocolVersion.TLS_1_0.getId(),
					random2.encode(false), suites1, new byte[]{(byte)0x00}},
				{"Protocol version SSL 3.0",EProtocolVersion.SSL_3_0.getId(),
					random2.encode(false), suites1, new byte[]{(byte)0x00}},
				{"Protocol version TLS 1.2",EProtocolVersion.TLS_1_2.getId(),
					random2.encode(false), suites1, new byte[]{(byte)0x00}},
				{"TLS_DHE_DSS and TLS_DH_DSS Cipher suites",EProtocolVersion.TLS_1_0.getId(),
					random2.encode(false), suites2, new byte[]{(byte)0x00}},
				{"Compression method 0x01",EProtocolVersion.TLS_1_0.getId(),
					random2.encode(false), suites1, new byte[]{(byte)0x01}},
				{"No cipher suites defined",EProtocolVersion.TLS_1_0.getId(),
					random2.encode(false), suites4, new byte[]{(byte)0x00}},
				{"No cipher but comp-method 0x01",EProtocolVersion.TLS_1_0.getId(),
					random2.encode(false), suites4, new byte[]{(byte)0x01}},
        };
    }
	
	/**
     * Start SSL handshake.
	 * @throws InterruptedException 
	 * @throws IOException 
     */
	 @Test(enabled = true, dataProvider = "clientHello")
	 public void fingerprintClientHello(String desc, byte [] protocolVersion, 
				byte [] random, ECipherSuite [] suites, byte [] compMethod){
		 workflow = new SSLHandshakeWorkflow();
		 workflow.connectToTestServer(HOST, PORT);
		 workflow.addObserver(this, EStates.CLIENT_HELLO);
		 CipherSuites cipherSuites = new CipherSuites();
		 cipherSuites.setSuites(suites);
		 this.protVersion=protocolVersion;
		 this.cipherSuites=cipherSuites.encode(false);
		 this.random=random;
		 this.compMethod=compMethod;
		 workflow.start();
		 System.out.println("Test No." + this.counter +" : " + desc);
		 TraceListAnalyzer analyze = new TraceListAnalyzer();
		 analyze.logOutput(workflow.getTraceList());
		 System.out.println("------------------------------");
		 this.counter++;
	 }
	 
	 /**
	  * Update observed object.
	  * @param o Observed object
	  * @param arg Arguments
	  */
	 @Override
	 public void update(Observable o, Object arg) {
		 MessageBuilder msgBuilder = new MessageBuilder();
		 Trace trace = null;
		 EStates states = null;
		 ObservableBridge obs;
		 if (o instanceof ObservableBridge) {
			 obs = (ObservableBridge) o;
			 states = (EStates) obs.getState();
			 trace = (Trace) arg;
		 }
		 if (states == EStates.CLIENT_HELLO ){
			 ClientHello clientHello = msgBuilder.createClientHello(protVersion, random, cipherSuites, compMethod);
			 trace.setCurrentRecord(clientHello);
		 }

	 }
	
	/**
     * Close the Socket after the test run.
     */
    @AfterMethod
    public void tearDown(){
    	try {
    		workflow.getSocket().close();
		} catch (IOException e) {
			e.printStackTrace();
		} 
    }
	

}
