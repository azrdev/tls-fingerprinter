package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

/**
 * ExchangeKeys Interface as used in the ClientKeyExchange message of SSL/TLS.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jan 17, 2012
 */
public interface IExchangeKeys {
    // a marker interface to support generics for the ClientKeyExchange message

    /**
     * Decodes a given byte array into a valid object if possible.
     *
     * @param message Byte representation of the message
     * @param chained Decode single or chained with underlying frames
     */
    void decode(final byte[] message, final boolean chained);

    /**
     * Encodes this object.
     *
     * @param chained Encode single or chained with underlying frames as valid
     * record layer frame
     * @return Encoded form of this object as specified in RFC-2246
     */
    byte[] encode(final boolean chained);
}
