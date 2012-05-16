package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CompressionMethod;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.SessionId;

public class ClientHelloAnalyzer implements IMessageAnalyzer {
	
	public static final int parametersToCheck = 5;

	public ClientHelloAnalyzer() {
		
	}
	@Override
	public void compareMessages(ARecordFrame currentRecord,
			ARecordFrame oldRecord) {
		ClientHello newClientHello = (ClientHello) currentRecord;
		ClientHello oldClientHello = (ClientHello) oldRecord;
		HashMap<String, Object> hm = new HashMap<String, Object>();
		EProtocolVersion protVersion = newClientHello.getProtocolVersion();
		RandomValue random = newClientHello.getRandom();
		SessionId sessionId = newClientHello.getSessionID();
		ECipherSuite [] cipher = newClientHello.getCipherSuites();
		byte [] compMethod = newClientHello.getCompressionMethod();
		if (!(protVersion.equals(oldClientHello.getProtocolVersion()))) {
			hm.put("protocolVersion", protVersion);
		}
		if (!(random.equals(oldClientHello.getProtocolVersion()))) {
			hm.put("random", random);
		}
		if (!(sessionId.equals(oldClientHello.getSessionID()))) {
			hm.put("sessionId", sessionId);
		}
		if (!(cipher.equals(oldClientHello.getCipherSuites()))) {
			hm.put("cipherSuite", cipher);
		}
		if (!(compMethod.equals(oldClientHello.getCompressionMethod()))) {
			hm.put("compressionMethod", compMethod);
		}
		 
	}
	
	


}
