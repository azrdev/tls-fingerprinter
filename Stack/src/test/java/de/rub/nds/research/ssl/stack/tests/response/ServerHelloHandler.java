package de.rub.nds.research.ssl.stack.tests.response;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import de.rub.nds.research.ssl.stack.protocols.commons.EBulkCipherAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherType;
import de.rub.nds.research.ssl.stack.protocols.commons.EMACAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.commons.EModeOfOperation;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;

/**
 * Handles a Server Hello message. The handler
 * extract parameters from the message which are
 * used in the following handshake processing.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * May 02, 2012
 */
public class ServerHelloHandler implements IHandshakeStates {
	
	/**
	 * Server hello message.
	 */
	private ServerHello serverHello;
	/**
	 * Length of initialization vector in AES.
	 */
	private static final int IV_LENGTH_AES = 16;
	/**
	 * Length of initialization vector
	 */
	private static final int IV_LENGTH = 8;
	/**
	 * SHA1 hash length.
	 */
	private static final int LENGTH_SHA1 = 20;
	/**
	 * MD5 hash length.
	 */
	private static final int LENGTH_MD5 = 16;
	/**
	 * Key size DES40.
	 */
	private static final int KEY_SIZE_DES40 = 5;
	/**
	 * Key size 3DES.
	 */
	private static final int KEY_SIZE_3DES = 24;
	/**
	 * Key size DES.
	 */
	private static final int KEY_SIZE_DES = 8;
	
	 /**
     * Initialize the log4j logger.
     */
	static Logger logger = Logger.getRootLogger();
	
	
	/**
	 * Empty constructor
	 */
	public ServerHelloHandler() {
	}

	/**
	 * Extract the server random and the security
	 * parameters from Server Hello.
	 * @param handRecord Handshake record
	 */
	@Override
	public final void handleResponse(final AHandshakeRecord handRecord) {
		serverHello = (ServerHello) handRecord;
		logger.debug("Chosen cipher: " + serverHello.getCipherSuite().name());
		this.setServerRandom();
		this.setSecurityParameters(serverHello.getCipherSuite());
	}
	
	/**Extracts the server random from the ServerHello.
	 */
	public final void setServerRandom() {
		SecurityParameters param = SecurityParameters.getInstance();
		byte [] serverRandom = null;
		byte [] serverTime = serverHello.getRandom().getUnixTimestamp();
		byte [] serverValue = serverHello.getRandom().getValue();
		serverRandom = new byte[serverTime.length + serverValue.length];
		int pointer = 0;
		//copy the client random to the array
		System.arraycopy(serverTime, 0, serverRandom,
				pointer, serverTime.length);
		pointer += serverTime.length;
		System.arraycopy(serverValue, 0, serverRandom,
				pointer, serverValue.length);
		
		param.setServerRandom(serverRandom);
	}
	
	/**Sets necessary security parameters using the cipher suite.
	 * @param cipher Cipher suite from the ServerHello message
	 */
    public final void setSecurityParameters(final ECipherSuite cipher) {
    	SecurityParameters param = SecurityParameters.getInstance();
    	String suiteString = cipher.toString();
    	String [] suiteParams = suiteString.split("_");
    	List<String> suiteList = new ArrayList<String>();
    	for (String i : suiteParams) {
    		suiteList.add(i);
    	}
    	suiteList.remove(0);
    	setKeyExchangeAlgorithm(suiteList);
    	setExportable(suiteList);
    	setBulkCipher(suiteList);
    	setMACAlgorithm(suiteList);
    	if (param.getBulkCipherAlgorithm().name().equals("AES")) {
    		param.setKeyMaterialLength((param.getHashSize() * 2)
    				+ (param.getKeySize() * 2) + IV_LENGTH_AES * 2);
    	}
    	else {
    		param.setKeyMaterialLength((param.getHashSize() * 2)
    				+ (param.getKeySize() * 2) + IV_LENGTH * 2);
    	}
    	
    	
    }

    /**Sets key exchange algorithm.
     * @param suiteList List of cipher cuite parameters
     */
    private final void setKeyExchangeAlgorithm(final List<String> suiteList) {
    	KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
    	if (suiteList.get(0).equals("RSA")) {
    		keyParams.setKeyExchangeAlgorithm(
    				EKeyExchangeAlgorithm.valueOf("RSA"));
    		suiteList.remove(0);
    		}
    	else if (suiteList.get(0).equals("DH") ||
    			suiteList.get(0).equals("DHE")) {
    		keyParams.setKeyExchangeAlgorithm(
    				EKeyExchangeAlgorithm.valueOf("DIFFIE_HELLMAN"));
    		suiteList.remove(0);
    		keyParams.setSignatureAlgorithm(
    				ESignatureAlgorithm.valueOf(suiteList.get(0)));
    		suiteList.remove(0);
    		}
    }
    
    /**
     * Set the flag for exportable cipher suites.
     * @param suiteList List of cipher cuite parameters
     */
    private final void setExportable(final List<String> suiteList) {
    	SecurityParameters param = SecurityParameters.getInstance();
    	if (suiteList.get(0).equals("EXPORT")) {
    		param.setExportable(true);
    		suiteList.remove(0);
    		suiteList.remove(0);
    	} else {
			suiteList.remove(0);
		}
    }
    
    /**
     * Set the bulk cipher
     * @param suiteList List of cipher cuite parameters
     */
    private final void setBulkCipher(final List<String> suiteList) {  
    	SecurityParameters param = SecurityParameters.getInstance();
    	EBulkCipherAlgorithm algorithm = EBulkCipherAlgorithm.NULL;
    	if (suiteList.get(0).equals("RC4")) {
    		param.setCipherType(ECipherType.STREAM);
    	}
    	else {
    		param.setCipherType(ECipherType.BLOCK);
    	}
    	switch (algorithm.getBulkCipher(suiteList.get(0))) {
    	case NULL: 	param.setBulkCipherAlgorithm(EBulkCipherAlgorithm.NULL);
    				suiteList.remove(0);
    				break;
    	case RC4:	param.setBulkCipherAlgorithm(EBulkCipherAlgorithm.RC4);
					suiteList.remove(0);
					param.setKeySize(
							Integer.valueOf(suiteList.get(0)) / 8);
					suiteList.remove(0);
					break;
    	case RC2:	param.setBulkCipherAlgorithm(EBulkCipherAlgorithm.RC2);
    				suiteList.remove(0);
    				param.setModeOfOperation(
    						EModeOfOperation.valueOf(suiteList.get(0)));
    				suiteList.remove(0);
    				param.setKeySize(
    						Integer.valueOf(suiteList.get(0)) / 8);
					suiteList.remove(0);
					break;
    	case DES:	param.setBulkCipherAlgorithm(EBulkCipherAlgorithm.DES);
    				param.setKeySize(KEY_SIZE_DES);
    				suiteList.remove(0);
    				param.setModeOfOperation(
    						EModeOfOperation.valueOf(suiteList.get(0)));
    				suiteList.remove(0);
    				break;
    	case DES40:	param.setBulkCipherAlgorithm(
    					EBulkCipherAlgorithm.DES40);
    				param.setKeySize(KEY_SIZE_DES40);
    				suiteList.remove(0);
    				param.setModeOfOperation(
    						EModeOfOperation.valueOf(suiteList.get(0)));
    				suiteList.remove(0);
    				break;
    	case TripleDES: 
    				param.setBulkCipherAlgorithm(
    						EBulkCipherAlgorithm.TripleDES);
    				param.setKeySize(KEY_SIZE_3DES);
    				suiteList.remove(0);
    				suiteList.remove(0);
    				param.setModeOfOperation(
    						EModeOfOperation.valueOf(suiteList.get(0)));
    				suiteList.remove(0);
    				break;
    	case AES:	param.setBulkCipherAlgorithm(EBulkCipherAlgorithm.AES);
    				suiteList.remove(0);
					param.setKeySize(
							Integer.valueOf(suiteList.get(0)) / 8);
					suiteList.remove(0);
					param.setModeOfOperation(
							EModeOfOperation.valueOf(suiteList.get(0)));
					suiteList.remove(0);
					break;
		default: 	break;		
    	}
    }
    
    /**
     * Set the MAC Algorithm
     * @param suiteList List of cipher suite parameters
     */
    private final void setMACAlgorithm(final List<String> suiteList) {
    	SecurityParameters param = SecurityParameters.getInstance();
    	if (suiteList.get(0).equals("SHA")) {
    		param.setMacAlgorithm(EMACAlgorithm.valueOf("SHA1"));
    		param.setHashSize(LENGTH_SHA1);
    	}
    	else {
    		param.setMacAlgorithm(EMACAlgorithm.valueOf("MD5"));
    		param.setHashSize(LENGTH_MD5);
    	}
    }

	
	

}
