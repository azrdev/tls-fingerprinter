package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;

/**
 * Defines the ClientKeyExchange parameters for fingerprinting tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum
 * @version 0.1
 * Jun. 21, 2012
 */
public class ClientKeyExchangeParameters extends AParameters {
	
	/**Cipher suite for tests*/
	private ECipherSuite[] cipherSuite;
	/**ClientKeyExchange payload*/
	private byte [] payload;
	
	public ECipherSuite[] getCipherSuite() {
		return this.cipherSuite;
	}
	
	public void setCipherSuite(ECipherSuite[] cipherSuite) {
		this.cipherSuite = cipherSuite;
	}
	
	/**
	 * Get the value of the ChangeCipherSpec payload.
	 * @return ChangeCipherSpec payload
	 */
	public byte[] getPayload() {
		if (this.payload != null) {
			return this.payload.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the value of the ChangeCipherSpec payload.
	 * @param payload ChangeCipherSpec payload
	 */
	public void setPayload(byte[] payload) {
		if (payload != null) {
			this.payload = payload.clone();
		}
		else {
			this.payload = null;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String computeHash() {
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		updateHash(sha1, getTestClassName().getBytes());
		updateHash(sha1, getDescription().getBytes());
		updateHash(sha1, getPayload());
		byte [] hash = sha1.digest();
		String hashValue = Utility.bytesToHex(hash);
		hashValue = hashValue.replace(" ", "");
		return hashValue;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void updateHash(MessageDigest sha1, byte[] input) {
		if (input != null) {
			sha1.update(input);
		}
	}

}
