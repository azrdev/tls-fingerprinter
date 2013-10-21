package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

/**
 * Interface for cipher computation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 23, 2012
 */
public interface IGenericCipher {

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
