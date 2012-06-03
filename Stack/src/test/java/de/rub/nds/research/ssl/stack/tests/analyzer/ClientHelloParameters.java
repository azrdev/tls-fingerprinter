package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;

/**
 * Defines the client hello parameters for fingerprinting tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 02, 2012
 */
public class ClientHelloParameters extends AParameters {
	
	/**Timestamp in the random value.*/
	private byte [] timestamp = null;
	/**Byte to separate random from the rest of the message.*/
	private byte[] randomSeparate = null;
	/**Session Id of the ClientHello message.*/
	private byte[] sessionId = null;
	/**Value of the sessionId length field*/
	private byte[] sessionIdLen = null;
	/**Value of the cipher suite length field.*/
	private byte[] cipherLen = null;
	/**Compression method.*/
	private byte[] compMethod = null;
	/**Test class name.*/
	private String name;

	/**
	 * Get the timestamp of the random value.
	 * @return Timestamp
	 */
	public byte[] getTimestamp() {
		if (this.timestamp != null) {
			return this.timestamp.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the timestamp of the random value.
	 * @param timestamp Timestamp
	 */
	public void setTimestamp(byte[] timestamp) {
		if (timestamp != null) {
			this.timestamp = timestamp;
		}
	}
	
	/**
	 * Get the separate byte between random value and the
	 * rest of the ClientHello message.
	 * @return Separate byte
	 */
	public byte[] getRandomSeparate() {
		if (this.randomSeparate != null) {
			return this.randomSeparate.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the separate byte between random value and the
	 * rest of the ClientHello message.
	 * @param randomSeparate Separate byte
	 */
	public void setRandomSeparate(byte[] randomSeparate) {
		if (randomSeparate != null) {
			this.randomSeparate = randomSeparate.clone();
		}
	}
	
	/**
	 * Get the session ID od the ClientHello message.
	 * @return Session ID
	 */
	public byte[] getSessionId() {
		if (this.sessionId != null) {
			return sessionId.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the session ID od the ClientHello message.
	 * @param sessionId Session ID
	 */
	public void setSessionId(byte[] sessionId) {
		if (sessionId != null) {
			this.sessionId = sessionId.clone();
		}
	}
	
	/**
	 * Get the value of the session ID length field.
	 * @return Value of the session ID length field
	 */
	public byte[] getSessionIdLen() {
		if (this.sessionIdLen != null) {
			return sessionIdLen.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the value of the session ID length field.
	 * @param sessionIdLen Value of the session ID length field
	 */
	public void setSessionIdLen(byte[] sessionIdLen) {
		if (sessionIdLen != null) {
			this.sessionIdLen = sessionIdLen.clone();
		}
	}
	
	/**
	 * Get the value of the cipher suite length field.
	 * @return Value of the cipher suite length field
	 */
	public byte[] getCipherLen() {
		if (this.cipherLen != null) {
			return this.cipherLen.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the value of the cipher suite length field.
	 * @param cipherLen Value of the cipher suite length field
	 */
	public void setCipherLen(byte[] cipherLen) {
		if (cipherLen != null) {
			this.cipherLen = cipherLen.clone();
		}
	}
	
	/**
	 * Get the compression method.
	 * @return Compression method
	 */
	public byte[] getCompMethod() {
		if (this.compMethod != null) {
			return this.compMethod.clone();
		}
		else {
			return null;
		}
	}
	
	/**
	 * Set the compression method.
	 * @param compMethod Compression method
	 */
	public void setCompMethod(byte[] compMethod) {
		if (compMethod != null) {
			this.compMethod = compMethod.clone();
		}
	}
	
	/**
	 * Get the name of the test class.
	 * @return Test class name
	 */
	public String getTestClassName() {
		return name;
	}
	
	/**
	 * Set the name of the test class.
	 * @param className Test class name
	 */
	public void setTestClassName(String name) {
		this.name = name;
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
		updateHash(sha1, getTimestamp());
		updateHash(sha1, getRandomSeparate());
		updateHash(sha1, getSessionId());
		updateHash(sha1, getSessionIdLen());
		updateHash(sha1, getCipherLen());
		updateHash(sha1, getCompMethod());
		byte [] hash = sha1.digest();
		String hashValue = Utility.byteToHex(hash);
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
