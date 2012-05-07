package de.rub.nds.research.ssl.stack.tests.response;

import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;

public interface IHandshakeStates {
	
	public void handleResponse(AHandshakeRecord handRecord);

}
