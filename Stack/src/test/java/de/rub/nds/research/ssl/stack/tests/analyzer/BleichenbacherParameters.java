package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;

/**
 * Defines the test parameters used for Bleichenbacher Test.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * 24 May, 2012
 */
public class BleichenbacherParameters extends AParameters {
	
	/**
	 * Mode as defined in PKCS#1 standard.
	 */
	private byte [] mode = null;
	/**
	 * Separate byte between padding and data.
	 */
	private byte [] separate = null;
	/**
	 * PreMasterSecret protocol version
	 */
	private EProtocolVersion protocolVersion;
	/**
	 * Signalizes if padding should be changed.
	 */
	private boolean changePadding;
	/**
	 * Position where padding is changed.
	 */
	private int position;
	
	/**
	 * Get the mode as defined in PKCS#1 standard.
	 * @return Mode
	 */
	public byte[] getMode() {
		return mode.clone();
	}
	
	/**
	 * Set the mode as defined in PKCS#1 standard.
	 * @param mode Mode
	 */
	public void setMode(byte[] mode) {
		this.mode = mode.clone();
	}
	/**
	 * Get the separate byte between padding and data.
	 * @return Separate byte
	 */
	public byte[] getSeparate() {
		return separate.clone();
	}
	
	/**
	 * Set the separate byte between padding and data.
	 * @param separate Separate byte
	 */
	public void setSeparate(byte[] separate) {
		this.separate = separate.clone();
	}
	
	/**
	 * Get the protocol version of the PreMasterSecret.
	 * @return Protocol version of PreMasterSecret
	 */
	public EProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}
	
	/**
	 * Set the protocol version of the PreMasterSecret.
	 * @param protocolVersion Protocol version of PreMasterSecret
	 */
	public void setProtocolVersion(EProtocolVersion protocolVersion) {
		this.protocolVersion = protocolVersion;
	}
	
	/**
	 * Signalizes if padding is changed.
	 * @return True if padding is changed
	 */
	public boolean isChangePadding() {
		return changePadding;
	}
	
	/**
	 * Set boolean to change the padding.
	 * @param changePadding Set to true to change padding
	 */
	public void setChangePadding(boolean changePadding) {
		this.changePadding = changePadding;
	}
	
	/**
	 * Get the position where padding is changed.
	 * @return Position
	 */
	public int getPosition() {
		return position;
	}
	
	/**
	 * Set the position where padding is changed.
	 * @param position Position where padding is changed
	 */
	public void setPosition(int position) {
		this.position = position;
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
		updateHash(sha1, getMode());
		updateHash(sha1, getSeparate());
		updateHash(sha1, getProtocolVersion().getId());
		updateHash(sha1, String.valueOf(getPosition()).getBytes());
		updateHash(sha1, String.valueOf(isChangePadding()).getBytes());
		byte [] hash = sha1.digest();
		String hashValue = Utility.byteToHex(hash);
		hashValue = hashValue.replace(" ", "");
		return hashValue;
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public void updateHash(MessageDigest sha1, byte [] input) {
		if (input != null) {
			sha1.update(input);
		}
	}

}
