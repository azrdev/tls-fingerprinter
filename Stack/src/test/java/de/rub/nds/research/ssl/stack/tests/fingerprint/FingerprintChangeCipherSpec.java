package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Observable;
import java.util.Observer;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;

public class FingerprintChangeCipherSpec implements Observer{

	/**Handshake workflow to observe.*/
	private SSLHandshakeWorkflow workflow;
	/**Help utilities for testing.*/
	private SSLTestUtils utils = new SSLTestUtils();
	/**Test host.*/
    private static final String HOST = "localhost";
    /**Test port.*/
    private static final int PORT = 8443;
	
	/**Test parameters.*/
	private EProtocolVersion pVersion;
	private byte[] payload;
	
	
	/** Test parameters for ChangeCipherSpec fingerprinting.
	 * @return List of parameters
	 */
    @DataProvider(name = "changeCipherSpec")
    public Object[][] createData1() {
        return new Object[][]{
//				{EProtocolVersion.TLS_1_0, new byte[]{0x01}}, 	//ok case
				{EProtocolVersion.TLS_1_0, new byte[]{0x02,0x01}}	//wrong payload
				
        };
    }
	
	/**
     * Start SSL handshake.
	 * @throws InterruptedException 
	 * @throws IOException 
     */
	 @Test(enabled = true, dataProvider = "changeCipherSpec")
	 public void fingerprintClientHello(EProtocolVersion protocolVersion,
			 byte[] payload){
		 workflow = new SSLHandshakeWorkflow();
		 workflow.connectToTestServer(HOST, PORT);
		 workflow.addObserver(this, EStates.CLIENT_CHANGE_CIPHER_SPEC);
		 this.pVersion=protocolVersion;
		 this.payload=payload;
		 workflow.start();
	 }
	 
	 /**
	  * Update observed object.
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
		 if (states == EStates.CLIENT_CHANGE_CIPHER_SPEC) {
			 ChangeCipherSpec ccs = new ChangeCipherSpec(pVersion);
			 ccs.setContent(payload);
			 trace.setCurrentRecord(ccs);
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
