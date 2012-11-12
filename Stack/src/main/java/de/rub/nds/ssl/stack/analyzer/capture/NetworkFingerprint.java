package de.rub.nds.ssl.stack.analyzer.capture;

import de.rub.nds.virtualnetworklayer.p0f.Label;

public class NetworkFingerprint {
	private String os;
	private int ttl;
	
	public NetworkFingerprint(Label l, int ttl) {
		this.os = l.toString();
		this.ttl = ttl;
	}

	public String getOs() {
		return os;
	}

	public void setOs(String os) {
		this.os = os;
	}

	public int getTtl() {
		return ttl;
	}

	public void setTtl(int ttl) {
		this.ttl = ttl;
	}
	
	public String toString() {
		return "NetworkFingerprint: ttl = " + this.getTtl() + ", os = " + this.getOs();
	}
	
	@Override
	public int hashCode() {
		return this.toString().hashCode();
	}

	public boolean equals(Object o) {
		if (o instanceof NetworkFingerprint) {
			NetworkFingerprint nf = (NetworkFingerprint) o;
			return this.getOs().equals(nf.getOs()) && (this.getTtl() == nf.getTtl());
		} else {
			return super.equals(o);
		}
	}

}
