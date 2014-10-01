package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerECDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerRSAParams;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.TLSSignature;
import org.apache.log4j.Logger;

import java.util.Arrays;

/**
 * Defines the ServerKeyExchange message of SSL/TLS as defined in RFC 2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Apr 17, 2012
 */
public class ServerKeyExchange extends AHandshakeRecord {
    private static Logger logger = Logger.getLogger(ServerKeyExchange.class);

    /**
     * Key exchange algorithm used in the handshake.
     */
    private EKeyExchangeAlgorithm keyExchangeAlgorithm;
    /**
     * Exchange keys.
     */
    private IExchangeKeys exchangeKeys;
    /**
     * Signature of the parameters.
     */
    private TLSSignature signature;

    private void setKeyExchangeAlgorithm(EKeyExchangeAlgorithm kea) {
        this.keyExchangeAlgorithm = kea;
        KeyExchangeParams keyExchangeParams = KeyExchangeParams.getInstance();
        keyExchangeParams.setKeyExchangeAlgorithm(kea);
    }

    /**
     * Initializes a ServerKeyExchange message as defined in RFC 2246.
     *
     * @param message ServerKeyExchange message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public ServerKeyExchange(final byte[] message,
            final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        this.setKeyExchangeAlgorithm(keyParams.getKeyExchangeAlgorithm());
        this.decode(message, chained);
    }

    /**
     * Initializes a ServerKeyExchange message as defined in RFC 2246.
     *
     * @param message ServerKeyExchange message in encoded form
     * @param exchangeAlgorithm Key exchange algorithm to be used
     * @param chained Decode single or chained with underlying frames
     */
    public ServerKeyExchange(final byte[] message,
            final EKeyExchangeAlgorithm exchangeAlgorithm,
            final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.setKeyExchangeAlgorithm(exchangeAlgorithm);
        this.setMessageType(EMessageType.SERVER_KEY_EXCHANGE);
        this.decode(message, chained);
    }

    /**
     * Initializes a ServerKeyExchange message as defined in RFC 2246.
     *
     * @param protocolVersion Protocol version of this message
     * @param exchangeAlgorithm Key exchange algorithm to be used
     */
    public ServerKeyExchange(final EProtocolVersion protocolVersion,
            final EKeyExchangeAlgorithm exchangeAlgorithm) {
        super(protocolVersion, EMessageType.SERVER_KEY_EXCHANGE);
        this.setKeyExchangeAlgorithm(exchangeAlgorithm);
    }

    /**
     * Get the exchange keys.
     *
     * @return Key exchange keys of this message
     */
    public final IExchangeKeys getExchangeKeys() {
        byte[] tmp;

        tmp = this.exchangeKeys.encode(false);
        switch (this.keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                return new ServerDHParams(tmp);
            case RSA:
                return new ServerRSAParams(tmp);
            case EC_DIFFIE_HELLMAN:
                return new ServerECDHParams(tmp);
            default:
                return null;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        byte[] params;
        int pointer = 0;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // security parameters
        if(keyExchangeAlgorithm == null)
            throw new IllegalStateException("KeyExchangeAlgorithm null");

        switch (keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                exchangeKeys = new ServerDHParams(payloadCopy);
                break;
            case RSA:
                exchangeKeys = new ServerRSAParams(payloadCopy);
                break;
            case EC_DIFFIE_HELLMAN:
                exchangeKeys = new ServerECDHParams(payloadCopy);
                break;
            default:
                break;
        }

        /*
         * maybe better make Server*Params an abstract class,
         * which extracts & checks signature itself
         */

        // get the part of payloadCopy that was captured by the parameters (esp. its length)
        params = exchangeKeys.encode(false);
        if(params.length > payloadCopy.length) {
            throw new IllegalArgumentException(
                    "Error parsing ServerKeyExchange Parameters");
        }
        pointer += params.length;

        // signature over parameters
        byte[] signatureBytes = Arrays.copyOfRange(payloadCopy, pointer,
                payloadCopy.length);
        try {
            signature = new TLSSignature(signatureBytes, params);
        } catch(IllegalArgumentException|IllegalStateException ex) {
            logger.warn("Error checking signature: " + ex);
        }
    }
}
