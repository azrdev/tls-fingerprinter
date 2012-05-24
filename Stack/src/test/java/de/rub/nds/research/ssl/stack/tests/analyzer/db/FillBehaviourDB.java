package de.rub.nds.research.ssl.stack.tests.analyzer.db;

import java.sql.Connection;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

import de.rub.nds.research.ssl.stack.tests.analyzer.BleichenbacherParameters;

public class FillBehaviourDB {
	
	private static Database db = new Database();
	
	public static void main(String args[]) {
		try {
			insertBehaviour();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public static void insertBehaviour() throws Exception {
		Connection conn = db.getConnection();
		java.sql.PreparedStatement prepared = conn.prepareStatement("insert into tls_fingerprint_hash"
				+ " values (default,?,?,?,?,?,?)");
		BleichenbacherParameters parameters = new BleichenbacherParameters();
		parameters.setChangePadding(false);
		parameters.setMode(new byte[]{0x00,0x02});
		parameters.setSeparate(new byte[]{0x00});
		parameters.setProtocolVersion(EProtocolVersion.SSL_3_0);
		parameters.setPosition(0);
		String fingerprint = parameters.computeFingerprint();
		prepared.setString(1, fingerprint);
		prepared.setString(2, "ALERT");
		prepared.setString(3, "HANDSHAKE_FAILURE");
		prepared.setString(4, "SERVER_CHANGE_CIPHER_SPEC");
		prepared.setString(5, "JSSE_STANDARD");
		prepared.setInt(6, 2);
		prepared.executeUpdate();
	}

}
