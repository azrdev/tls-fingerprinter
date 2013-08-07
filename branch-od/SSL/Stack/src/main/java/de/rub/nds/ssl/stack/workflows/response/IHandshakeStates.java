package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;

public interface IHandshakeStates {

    public void handleResponse(AHandshakeRecord handRecord);
}
