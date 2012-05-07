package de.rub.nds.research.ssl.stack.tests.response;

import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ServerDHParams;

public class ServerKeyExchangeHandler implements IHandshakeStates {
	
	private ServerKeyExchange serverKeyExchange;
	
	public ServerKeyExchangeHandler(){
	}
	
	@Override
	public void handleResponse(AHandshakeRecord handRecord) {
		serverKeyExchange = (ServerKeyExchange) handRecord;
		KeyExchangeParams keyExParams = KeyExchangeParams.getInstance();
		if (keyExParams.getKeyExchangeAlgorithm() == EKeyExchangeAlgorithm.DIFFIE_HELLMAN) {
		ServerDHParams params = new ServerDHParams(serverKeyExchange.getPayload());
		keyExParams.setDHGenerator(params.getDHGenerator());
		keyExParams.setDHPrime(params.getDHPrime());
		keyExParams.setDhPublic(params.getDHPublicValue());
		}
	}
	

}
