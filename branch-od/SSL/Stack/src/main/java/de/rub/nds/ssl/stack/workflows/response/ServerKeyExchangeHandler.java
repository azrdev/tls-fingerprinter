package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerECDHParams;

/**
 * Handles a Server Key Exchange message. The handler extract parameters from
 * the message which are used in the following handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 02, 2012
 */
public final class ServerKeyExchangeHandler implements IHandshakeStates {

    /**
     * Server key exchange.
     */
    private ServerKeyExchange serverKeyExchange;

    /**
     * Empty constructor.
     */
    public ServerKeyExchangeHandler() {
    }

    /**
     * Extract the key exchange parameters.
     *
     * @param handRecord Handshake record
     */
    @Override
    public void handleResponse(final AHandshakeRecord handRecord) {
        serverKeyExchange = (ServerKeyExchange) handRecord;
        KeyExchangeParams keyExParams = KeyExchangeParams.getInstance();
        switch (keyExParams.getKeyExchangeAlgorithm()) {
            case DIFFIE_HELLMAN:
                ServerDHParams dhParams = new ServerDHParams(serverKeyExchange.
                        getPayload());
                keyExParams.setDHGenerator(dhParams.getDHGenerator());
                keyExParams.setDHPrime(dhParams.getDHPrime());
                keyExParams.setDhPublic(dhParams.getDHPublicValue());
                break;
            case EC_DIFFIE_HELLMAN:
                ServerECDHParams ecdhParams =
                        new ServerECDHParams(serverKeyExchange.getPayload());
                keyExParams.setECDHParameters(ecdhParams.getCurveParameters());
                keyExParams.setECDHPublicPoint(ecdhParams.getPublicKey());
                break;
            default:
                break;
        }
    }
}
