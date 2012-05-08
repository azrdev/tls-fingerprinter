package de.rub.nds.research.ssl.stack.tests.response;

import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.research.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHelloDone;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;

public class HandshakeResponse {
	
	IHandshakeStates serverHello;
	IHandshakeStates certificate;
	IHandshakeStates serverKeyExchange;
	
	public HandshakeResponse(AHandshakeRecord handRecord, Trace trace, SSLHandshakeWorkflow workflow) {
		if (handRecord instanceof ServerHello) {
			serverHello = new ServerHelloHandler();
			serverHello.handleResponse(handRecord);
			workflow.switchToState(trace, EStates.SERVER_HELLO);
			trace.setCurrentRecord((ServerHello) handRecord);
		}
		if (handRecord instanceof Certificate) {
			certificate = new CertificateHandler();
			certificate.handleResponse(handRecord);
			workflow.switchToState(trace, EStates.SERVER_CERTIFICATE);
			trace.setCurrentRecord((Certificate) handRecord);
		}
		if (handRecord instanceof ServerKeyExchange) {
			serverKeyExchange = new ServerKeyExchangeHandler();
			serverKeyExchange.handleResponse(handRecord);
			workflow.switchToState(trace, EStates.SERVER_KEY_EXCHANGE);
			trace.setCurrentRecord((ServerKeyExchange) handRecord);
		}
		if (handRecord instanceof ServerHelloDone) {
			workflow.switchToState(trace, EStates.SERVER_HELLO_DONE);
			trace.setCurrentRecord((ServerHelloDone) handRecord);
		}
	}
	

}
