package de.rub.nds.ssl.analyzer.capture;

public class ServerFingerprintDifference {
	
	private ConnectionDifferenceSet mtuDifference;
	private ConnectionDifferenceSet tcpDifference;
	private ConnectionDifferenceSet serverHelloDifference;
	
	public ServerFingerprintDifference(ConnectionDifferenceSet mtuDifference,
			ConnectionDifferenceSet tcpDifference,
			ConnectionDifferenceSet serverHelloDifference) {
		super();
		this.mtuDifference = mtuDifference;
		this.tcpDifference = tcpDifference;
		this.serverHelloDifference = serverHelloDifference;
	}
	
	public ConnectionDifferenceSet getMtuDifference() {
		return mtuDifference;
	}
	
	public void setMtuDifference(ConnectionDifferenceSet mtuDifference) {
		this.mtuDifference = mtuDifference;
	}
	
	public ConnectionDifferenceSet getTcpDifference() {
		return tcpDifference;
	}
	
	public void setTcpDifference(ConnectionDifferenceSet tcpDifference) {
		this.tcpDifference = tcpDifference;
	}
	
	public ConnectionDifferenceSet getServerHelloDifference() {
		return serverHelloDifference;
	}
	
	public void setServerHelloDifference(
			ConnectionDifferenceSet serverHelloDifference) {
		this.serverHelloDifference = serverHelloDifference;
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("mtuDifference: " + mtuDifference);
		sb.append("\ntcpDifference: " + tcpDifference);
		sb.append("\nserverHelloDifference: " + serverHelloDifference);
		return new String(sb);
	}

}
