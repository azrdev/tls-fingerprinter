package de.rub.nds.research.ssl.stack.tests.analyzer.db;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;

public class FillBehaviourDB {
	
	public static void main(String args[]) {
		Database db = new Database();
		CipherSuites cipherSuites = new CipherSuites();
		cipherSuites.setSuites(new ECipherSuite[]{ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
		try {
			db.insertClientHelloBehaviour(EProtocolVersion.TLS_1_0.getId(),
					cipherSuites.encode(false), 32,
					32, new byte[]{0x01}, null, "jsse");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

}
