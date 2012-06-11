package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;

/**
 * Defines the Finished message parameters for fingerprinting tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 07, 2012
 */
public class FinishedParameters extends AParameters {
	
	/**Destroy the MAC of the Finished message.*/
	private boolean destroyMAC = false;
	/**Destroy the hash value of the handshake messages.*/
	private boolean destroyHash = false;
	/**Destroy the verify data of the Finished message.*/
	private boolean destroyVerify = false;
	/**Change the length byte of the padding string.*/
	private boolean changePadLength = false;
	/**Test class name.*/
	private String name;
	/**Description of the test case*/
	private String desc;
	
	
	/**
	 * Signalizes if MAC value should be destroyed.
	 * @return True if MAC is destroyed.
	 */
	public boolean isDestroyMAC() {
		return destroyMAC;
	}
	
	/**
	 * Set true if MAC should be destroyed.
	 * @param destroyMAC True if MAC is destroyed.
	 */
	public void setDestroyMAC(boolean destroyMAC) {
		this.destroyMAC = destroyMAC;
	}
	
	/**
	 * Signalizes if hash value should be destroyed.
	 * @return True if hash is destroyed.
	 */
	public boolean isDestroyHash() {
		return destroyHash;
	}
	
	/**
	 * Set true if hash should be destroyed.
	 * @param destroyMAC True if hash is destroyed.
	 */
	public void setDestroyHash(boolean destroyHash) {
		this.destroyHash = destroyHash;
	}
	
	/**
	 * Signalizes if Verify Data value should be destroyed.
	 * @return True if Verify Data is destroyed.
	 */
	public boolean isDestroyVerify() {
		return destroyVerify;
	}
	
	/**
	 * Set true if Verify Data should be destroyed.
	 * @param destroyMAC True if Verify Data is destroyed.
	 */
	public void setDestroyVerify(boolean destroyVerify) {
		this.destroyVerify = destroyVerify;
	}
	
	/**
	 * Signalizes if padding length byte is changed.
	 * @return True if padding length byte is changed
	 */
	public boolean isChangePadLength() {
		return changePadLength;
	}

	/**
	 * Set to true if padding length byte should be changed.
	 * @param changePadLength True if padding length byte is changed
	 */
	public void setChangePadLength(boolean changePadLength) {
		this.changePadLength = changePadLength;
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
	 * Get the description of a test case.
	 * @return Description of the test case
	 */
	public String getDescription() {
		return this.desc;
	}
	
	/**
	 * Set the description of a test case.
	 * @param desc Decription of the test case
	 */
	public void setDescription(String desc) {
		this.desc = desc;
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
		updateHash(sha1, String.valueOf(isDestroyMAC()).getBytes());
		updateHash(sha1, String.valueOf(isDestroyHash()).getBytes());
		updateHash(sha1, String.valueOf(isDestroyVerify()).getBytes());
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
