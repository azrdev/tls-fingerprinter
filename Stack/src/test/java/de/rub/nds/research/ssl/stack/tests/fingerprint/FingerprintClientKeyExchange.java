package de.rub.nds.research.ssl.stack.tests.fingerprint;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Observable;
import java.util.Observer;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.States;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;

public class FingerprintClientKeyExchange implements Observer {
	
	/**Handshake workflow to observe.*/
	private SSLHandshakeWorkflow workflow;
	/**Help utilities for testing.*/
	private SSLTestUtils utils = new SSLTestUtils();
	/**Test host.*/
    private static final String HOST = "localhost";
    /**Test port.*/
    private static final int PORT = 9443;
	
	/**Test parameters.*/
	private EProtocolVersion preMasterVersion;
	private EProtocolVersion pVersion;
	
	
	/** Test parameters for ClientKeyExchange fingerprinting.
	 * @return List of parameters
	 */
    @DataProvider(name = "clientKeyExchange")
    public Object[][] createData1() {
        return new Object[][]{
				{EProtocolVersion.TLS_1_0, EProtocolVersion.TLS_1_0} 	//ok case
        };
    }
	
	/**
     * Start SSL handshake.
	 * @throws InterruptedException 
	 * @throws IOException 
     */
	 @Test(enabled = true, dataProvider = "clientKeyExchange")
	 public void fingerprintClientHello(EProtocolVersion protocolVersion,
			 EProtocolVersion preMasterVersion){
		 workflow = new SSLHandshakeWorkflow();
		 workflow.connectToTestServer(HOST, PORT);
		 workflow.addObserver(this, States.CLIENT_KEY_EXCHANGE);
		 this.pVersion=protocolVersion;
		 this.preMasterVersion=preMasterVersion;
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
		 States states = null;
		 ObservableBridge obs;
		 if (o instanceof ObservableBridge) {
			 obs = (ObservableBridge) o;
			 states = (States) obs.getState();
			 trace = (Trace) arg;
		 }
		 if (states == States.CLIENT_KEY_EXCHANGE){
			 KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
             PublicKey pk = keyParams.getPublicKey();
			 ClientKeyExchange cke = new ClientKeyExchange(pVersion,
					 keyParams.getKeyExchangeAlgorithm());
			 PreMasterSecret pms = new PreMasterSecret(preMasterVersion);
			 workflow.setPreMasterSecret(pms);
			 //create encoded PMS
			 byte [] encodedPMS = pms.encode(false);
			 for (int i=0; i<encodedPMS.length; i++){
				 encodedPMS[i]=0x00;
			 }
			 //encrypted PreMasterSecret
			 EncryptedPreMasterSecret encPMS = new EncryptedPreMasterSecret(encodedPMS , pk);
			 cke.setExchangeKeys(encPMS);
			 trace.setCurrentRecord(cke);
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
