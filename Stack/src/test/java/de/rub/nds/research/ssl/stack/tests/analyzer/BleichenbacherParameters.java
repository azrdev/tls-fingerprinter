package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

public class BleichenbacherParameters {
	
	private byte [] mode = null;
	private byte [] separate = null;
	private EProtocolVersion protocolVersion;
	private boolean changePadding;
	private int position;
	
	public byte[] getMode() {
		return mode;
	}
	
	public void setMode(byte[] mode) {
		this.mode = mode;
	}
	
	public byte[] getSeparate() {
		return separate;
	}
	
	public void setSeparate(byte[] separate) {
		this.separate = separate;
	}
	
	public EProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}
	
	public void setProtocolVersion(EProtocolVersion protocolVersion) {
		this.protocolVersion = protocolVersion;
	}
	
	public boolean isChangePadding() {
		return changePadding;
	}
	
	public void setChangePadding(boolean changePadding) {
		this.changePadding = changePadding;
	}
	
	public int getPosition() {
		return position;
	}
	
	public void setPosition(int position) {
		this.position = position;
	}
	
	public String computeFingerprint() {
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		sha1.update(getMode());
		sha1.update(getSeparate());
		sha1.update(getProtocolVersion().getId());
		sha1.update(String.valueOf(getPosition()).getBytes());
		sha1.update(String.valueOf(isChangePadding()).getBytes());
		byte [] hash = sha1.digest();
		String fingerprint = Utility.byteToHex(hash);
		fingerprint = fingerprint.replace(" ", "");
		return fingerprint;
	}

}
