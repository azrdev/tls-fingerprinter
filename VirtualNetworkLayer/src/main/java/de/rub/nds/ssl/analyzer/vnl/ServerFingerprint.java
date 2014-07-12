package de.rub.nds.ssl.analyzer.vnl;

public class ServerFingerprint {
	private NetworkFingerprint networkFingerprint;
	private ServerHelloFingerprint serverHelloFingerprint;

	public ServerFingerprint(NetworkFingerprint networkFingerprint,
			ServerHelloFingerprint serverHelloFingerprint) {
		this.networkFingerprint = networkFingerprint;
		this.serverHelloFingerprint = serverHelloFingerprint;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime
				* result
				+ ((networkFingerprint == null) ? 0 : networkFingerprint
						.hashCode());
		result = prime
				* result
				+ ((serverHelloFingerprint == null) ? 0
						: serverHelloFingerprint.hashCode());
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
		ServerFingerprint other = (ServerFingerprint) obj;
		if (networkFingerprint == null) {
			if (other.networkFingerprint != null)
				return false;
		} else if (!networkFingerprint.equals(other.networkFingerprint))
			return false;
		if (serverHelloFingerprint == null) {
			if (other.serverHelloFingerprint != null)
				return false;
		} else if (!serverHelloFingerprint.equals(other.serverHelloFingerprint))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ServerFingerprint\n" +
				" networkFingerprint = " + networkFingerprint + "\n"
				+ "serverHelloFingerprint = " + serverHelloFingerprint;
	}

	public NetworkFingerprint getNetworkFingerprint() {
		return networkFingerprint;
	}
	
	public void setNetworkFingerprint(NetworkFingerprint networkFingerprint) {
		this.networkFingerprint = networkFingerprint;
	}
	
	public ServerHelloFingerprint getServerHelloFingerprint() {
		return serverHelloFingerprint;
	}
	
	public void setServerHelloFingerprint(ServerHelloFingerprint serverHelloFingerprint) {
		this.serverHelloFingerprint = serverHelloFingerprint;
	}
	
	public ServerFingerprintDifference getDifference(ServerFingerprint sf) {
		return new ServerFingerprintDifference(this.getNetworkFingerprint()
				.getMtuDifference(sf.getNetworkFingerprint()), this
				.getNetworkFingerprint().getTcpDifference(
						sf.getNetworkFingerprint()),
				ConnectionDifferenceSet.generateFromMap(this
						.getServerHelloFingerprint().getAsMap(), sf
						.getServerHelloFingerprint().getAsMap()));
	}
	
	
	

}
