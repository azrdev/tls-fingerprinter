package de.rub.nds.ssl.analyzer.capture;

import java.util.List;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;


public class NetworkFingerprint {
	private Fingerprint.Signature mtuFingerprint = null;
	private Fingerprint.Signature tcpFingerprint = null;
	
	
	
	
	public NetworkFingerprint(Fingerprint.Signature mtuFingerprint, Fingerprint.Signature tcpFingerprint) {
		this.mtuFingerprint = mtuFingerprint;
		this.tcpFingerprint = tcpFingerprint;
	}

	public NetworkFingerprint(List<Fingerprint.Signature> fingerprints) {
		this.mtuFingerprint = fingerprints.get(0);
		this.tcpFingerprint = fingerprints.get(1);
		if ((this.tcpFingerprint == null) || (this.mtuFingerprint == null)) {
			throw new RuntimeException("sorry, null fields passed to constructor");
		}
		
	}
	
	public String toString() {
		return "NetworkFingerprint: mtuFingerprint = " + mtuFingerprint + "\ntcpFingerprint = " + tcpFingerprint;
	}
	
	public Fingerprint.Signature getMtuFingerprint() {
		return mtuFingerprint;
	}

	public Fingerprint.Signature getTcpFingerprint() {
		return tcpFingerprint;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((mtuFingerprint == null) ? 0 : mtuFingerprint.hashCode());
		result = prime * result
				+ ((tcpFingerprint == null) ? 0 : tcpFingerprint.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		NetworkFingerprint other = (NetworkFingerprint) obj;
		if (mtuFingerprint == null) {
			if (other.mtuFingerprint != null)
				return false;
		} else if (!mtuFingerprint.equals(other.mtuFingerprint))
			return false;
		if (tcpFingerprint == null) {
			if (other.tcpFingerprint != null)
				return false;
		} else if (!tcpFingerprint.equals(other.tcpFingerprint))
			return false;
		return true;
	}

	
	public ConnectionDifferenceSet getMtuDifference(NetworkFingerprint b) {
		if (this.getMtuFingerprint() == null || b.getMtuFingerprint() == null) {
			return null;
		}
		return ConnectionDifferenceSet.generateFromMap(this.getMtuFingerprint().getSigns(), b.getMtuFingerprint().getSigns());
	}

	public ConnectionDifferenceSet getTcpDifference(NetworkFingerprint b) {
		if (this.getTcpFingerprint() == null || b.getTcpFingerprint() == null) {
			return null; 
		}
		return ConnectionDifferenceSet.generateFromMap(this.getTcpFingerprint().getSigns(), b.getTcpFingerprint().getSigns());
	}
}
