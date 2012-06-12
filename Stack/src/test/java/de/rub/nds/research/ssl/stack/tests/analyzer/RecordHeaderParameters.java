package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;

/**
 * Defines the record header parameters for fingerprinting tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 01, 2012
 */
public class RecordHeaderParameters extends AParameters {

	
	/**Record header message type.*/
	private byte [] msgType;
	/**Record header protocol version.*/
	private byte [] protocolVersion;
	/**Record header length field.*/
	private byte [] recordLength;
	/**Test class name.*/
	private String name;
	/**Decription of the test case*/
	private String desc;
	
	/**
	 * Get the name of the test class.
	 * @return Test class name
	 */
	public String getTestClassName() {
		return this.name;
	}
	
	/**
	 * Set the name of the test class.
	 * @param className Test class name
	 */
	public void setTestClassName(String className) {
		this.name = className;
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
	 * Get the record header message type.
	 * @return Message type
	 */
	public byte[] getMsgType() {
		if (msgType != null) {
			return msgType.clone();
		}
		else {
			return null;
		}
	}

	/**
	 * Set the record header message type.
	 * @param msgType Message type
	 */
	public void setMsgType(byte[] msgType) {
		if (msgType != null) {
			this.msgType = msgType.clone();
		}
		else { 
			this.msgType = null;
		}
	}

	/**
	 * Get the record header protocol version.
	 * @return Protocol version
	 */
	public byte[] getProtocolVersion() {
		if (protocolVersion != null) {
			return protocolVersion.clone();
		}
		else {
			return null;
		}
	}

	/**
	 * Set the record header protocol version.
	 * @param protocolVersion Protocol version
	 */
	public void setProtocolVersion(byte[] protocolVersion) {
		if (protocolVersion != null) {
			this.protocolVersion = protocolVersion.clone();
		}
		else {
			this.protocolVersion = null;
		}
	}

	/**
	 * Get the length field value of the record header.
	 * @return Length of the record
	 */
	public byte[] getRecordLength() {
		if (recordLength != null) {
			return recordLength.clone();
		}
		else {
			return null;
		}
	}

	/**
	 * Set the length field value of the record header.
	 * @param recordLength Length of the record
	 */
	public void setRecordLength(byte[] recordLength) {
		if (recordLength != null) {
			this.recordLength = recordLength.clone();
		}
		else {
			this.recordLength = null;
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
		updateHash(sha1, getMsgType());
		updateHash(sha1, getProtocolVersion());
		updateHash(sha1, getRecordLength());
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
