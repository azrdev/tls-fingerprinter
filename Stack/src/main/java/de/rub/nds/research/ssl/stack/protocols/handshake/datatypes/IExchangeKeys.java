package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

/**
 * ExchangeKeys Interface as used in the ClientKeyExchange message of SSL/TLS.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * Jan 17, 2012
 */
public interface IExchangeKeys {
    // a marker interface to support generics for the ClientKeyExchange message

    /**
     * {@inheritDoc}
     */
    void decode(final byte[] message, final boolean chained);

    /**
     * {@inheritDoc}
     */
    byte[] encode(final boolean chained);
}
