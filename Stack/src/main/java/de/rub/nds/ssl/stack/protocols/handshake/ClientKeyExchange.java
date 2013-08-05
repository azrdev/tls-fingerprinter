package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.*;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;

/**
 * Defines the ClientKeyExchange message of SSL/TLS as defined in RFC 2246
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 10, 2011
 */
public final class ClientKeyExchange extends AHandshakeRecord {

    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = 0;
    /**
     * Length bytes.
     */
    public static final int LENGTH_BYTES = 2;
    /**
     * Client values for the key exchange.
     */
    private IExchangeKeys exchangeKeys;
    /**
     * Key exchange algorithm.
     */
    private EKeyExchangeAlgorithm keyExchangeAlgorithm = null;

    /**
     * Initializes a ClientKeyExchange message as defined in RFC 2246.
     *
     * This constructor will skip the key exchange type. Use at your own risk.
     *
     * @param message ClientKeyExchange message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public ClientKeyExchange(final byte[] message,
            final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a ClientKeyExchange message as defined in RFC 2246.
     *
     * @param message ClientKeyExchange message in encoded form
     * @param exchangeAlgorithm Key exchange algorithm to be used
     * @param chained Decode single or chained with underlying frames
     */
    public ClientKeyExchange(final byte[] message,
            final EKeyExchangeAlgorithm exchangeAlgorithm,
            final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.keyExchangeAlgorithm =
                EKeyExchangeAlgorithm.valueOf(exchangeAlgorithm.name());
        this.decode(message, chained);
    }

    /**
     * Initializes a ClientKeyExchange message as defined in RFC 2246.
     *
     * @param protocolVersion Protocol version of this message
     * @param exchangeAlgorithm Key exchange algorithm to be used
     */
    public ClientKeyExchange(final EProtocolVersion protocolVersion,
            final EKeyExchangeAlgorithm exchangeAlgorithm) {
        super(protocolVersion, EMessageType.CLIENT_KEY_EXCHANGE);
        this.keyExchangeAlgorithm =
                EKeyExchangeAlgorithm.valueOf(exchangeAlgorithm.name());
    }

    /**
     * Set the key exchange algorithm (internal state only).
     *
     * @param algo Key exchange algorithm to be used.
     */
    public void setKeyExchangeAlgorithm(final EKeyExchangeAlgorithm algo) {
        if (algo == null) {
            throw new IllegalArgumentException(
                    "Key exchange algorithm MUST NOT be NULL.");
        }

        this.keyExchangeAlgorithm = EKeyExchangeAlgorithm.valueOf(algo.name());
    }

    /**
     * Set the protocol version at the record layer level.
     *
     * @param version Protocol version for the record Layer
     */
    public void setRecordLayerProtocolVersion(final EProtocolVersion version) {
        this.setProtocolVersion(version);
    }

    /**
     * Set the protocol version at the record layer level.
     *
     * @param version Protocol version for the record Layer
     */
    public void setRecordLayerProtocolVersion(final byte[] version) {
        this.setProtocolVersion(version);
    }

    /**
     * Get the exchange keys.
     *
     * @return Key exchange keys of this message
     */
    public IExchangeKeys getExchangeKeys() {
        IExchangeKeys keys = null;
        byte[] tmp;

        tmp = this.exchangeKeys.encode(false);
        switch (this.keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                keys = new ClientDHPublic(tmp);
                break;
            case RSA:
//                keys = new PreMasterSecret(tmp);
                keys = new EncPreMasterSecret(tmp);
                break;
            case EC_DIFFIE_HELLMAN:
                keys = new ClientECDHPublic(tmp);
                break;
            default:
                break;
        }

        return keys;
    }

    /**
     * Set exchange keys of this message.
     *
     * @param keys Exchange keys of this message
     */
    public void setExchangeKeys(final IExchangeKeys keys) {
        if (keys == null) {
            throw new IllegalArgumentException("Keys must not be NULL!");
        }

        setExchangeKeys(keys.encode(false));
    }

    /**
     * Set exchange keys of this message.
     *
     * @param keys Exchange keys of this message
     */
    public void setExchangeKeys(final byte[] keys) {
        if (keys == null) {
            throw new IllegalArgumentException("Keys must not be NULL!");
        }

        byte[] tmp = new byte[keys.length];
        System.arraycopy(keys, 0, tmp, 0, tmp.length);

        switch (this.keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                this.exchangeKeys = new ClientDHPublic(tmp);
                break;
            case RSA:
//          this.exchangeKeys = new PreMasterSecret(tmp);
//          RSA needs an encrypted PreMasterSecret
                this.exchangeKeys = new EncPreMasterSecret(tmp);
                break;
            case EC_DIFFIE_HELLMAN:
                this.exchangeKeys = new ClientECDHPublic(tmp);
                break;
            default:
                break;
        }
    }

    /**
     * {@inheritDoc}
     *
     * ClientKeyExchange representation 0 bytes
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] encodedExchangeKeys = this.exchangeKeys.encode(false);

        super.setPayload(encodedExchangeKeys);
        return chained ? super.encode(true) : encodedExchangeKeys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        switch (keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                if (payloadCopy.length
                        < ClientDHPublic.LENGTH_MINIMUM_ENCODED) {
                    throw new IllegalArgumentException(
                            "ClientKeyExchange message too short.");
                }
                exchangeKeys = new ClientDHPublic(payloadCopy);
                break;
            case RSA:
                if (payloadCopy.length
                        < PreMasterSecret.LENGTH_MINIMUM_ENCODED) {
                    throw new IllegalArgumentException(
                            "ClientKeyExchange message too short.");
                }
                exchangeKeys = new EncPreMasterSecret(payloadCopy);
                break;
            default:
                break;
        }

    }
}
