package de.rub.nds.ssl.stack.tests.response;

import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;

public interface IHandshakeStates {

    public void handleResponse(AHandshakeRecord handRecord);
}
