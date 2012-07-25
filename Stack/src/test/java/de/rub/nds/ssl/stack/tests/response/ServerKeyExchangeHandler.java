package de.rub.nds.ssl.stack.tests.response;

import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerDHParams;

/**
 * Handles a Server Key Exchange message. The handler extract parameters from
 * the message which are used in the following handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 02, 2012
 */
public class ServerKeyExchangeHandler implements IHandshakeStates {

    /**
     * Server key exchange.
     */
    private ServerKeyExchange serverKeyExchange;

    /**
     * Empty constructor
     */
    public ServerKeyExchangeHandler() {
    }

    /**
     * Extract the DHPrime, DHGenerator and DHPublic parameter.
     *
     * @param handRecord Handshake record
     */
    @Override
    public void handleResponse(AHandshakeRecord handRecord) {
        serverKeyExchange = (ServerKeyExchange) handRecord;
        KeyExchangeParams keyExParams = KeyExchangeParams.getInstance();
        if (keyExParams.getKeyExchangeAlgorithm()
                == EKeyExchangeAlgorithm.DIFFIE_HELLMAN) {
            ServerDHParams params = new ServerDHParams(serverKeyExchange.
                    getPayload());
            keyExParams.setDHGenerator(params.getDHGenerator());
            keyExParams.setDHPrime(params.getDHPrime());
            keyExParams.setDhPublic(params.getDHPublicValue());
        }
    }
}
