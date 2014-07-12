package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerECDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerRSAParams;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.TLSSignature;

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
        this.keyExchangeAlgorithm =
                keyParams.getKeyExchangeAlgorithm();
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
        this.keyExchangeAlgorithm = exchangeAlgorithm;
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
        this.keyExchangeAlgorithm = exchangeAlgorithm;
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        keyParams.setKeyExchangeAlgorithm(exchangeAlgorithm);
    }

    /**
     * Get the exchange keys.
     *
     * @return Key exchange keys of this message
     */
    public final IExchangeKeys getExchangeKeys() {
        IExchangeKeys keys = null;
        byte[] tmp;

        tmp = this.exchangeKeys.encode(false);
        switch (this.keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                keys = new ServerDHParams(tmp);
                break;
            case RSA:
                keys = new ServerRSAParams(tmp);
                break;
            case EC_DIFFIE_HELLMAN:
                keys = new ServerECDHParams(tmp);
                break;
            default:
                break;
        }

        return keys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        byte[] tmp;
        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

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

        tmp = exchangeKeys.encode(false);
        tmp = new byte[payloadCopy.length - tmp.length];
        System.arraycopy(payloadCopy, payloadCopy.length - tmp.length,
                tmp, 0, tmp.length);
        signature = new TLSSignature(tmp);
    }
}
