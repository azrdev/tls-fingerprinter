package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * Compression method message part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 15, 2011
 */
public final class CompressionMethod extends APubliclySerializable {

    /**
     * Length of the length field
     */
    private static final int LENGTH_LENGTH_FIELD = 1;
    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * Compression method
     */
    private byte[] methods = new byte[]{0x0};

    /**
     * Initializes a compression method object as defined in RFC-2246. Set by
     * default to 0x0!
     */
    public CompressionMethod() {
    }

    /**
     * Initializes a compression method object as defined in RFC-2246.
     *
     * @param message Compression method in encoded form
     */
    public CompressionMethod(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the compression method of this message.
     *
     * @return The compression method of this message
     */
    public byte[] getMethods() {
        // deep copy
        byte[] tmp = new byte[methods.length];
        System.arraycopy(methods, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the compression methods of this message.
     *
     * @param methods The compression methods to be used for this message
     */
    public final void setMethods(final byte[] methods) {
        if (methods == null) {
            throw new IllegalArgumentException(
                    "Compression methods must not be null!");
        }

        // deep copy
        this.methods = new byte[methods.length];
        System.arraycopy(methods, 0, this.methods, 0, methods.length);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding
     */
    @Override
    public byte[] encode(boolean chained) {
        byte[] tmp = new byte[methods.length + LENGTH_LENGTH_FIELD];
        tmp[0] = ((Integer) methods.length).byteValue();
        System.arraycopy(methods, 0, tmp, LENGTH_LENGTH_FIELD, methods.length);

        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding
     */
    public void decode(final byte[] message, final boolean chained) {
        final int methodsLength;
        final byte[] newMethods;
        // deep copy
        final byte[] methods = new byte[message.length];
        System.arraycopy(message, 0, methods, 0, methods.length);

        // check size
        if (methods.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "Compression methods record too short.");
        }

        methodsLength = methods[0];
        newMethods = new byte[methodsLength];
        System.arraycopy(methods, LENGTH_LENGTH_FIELD, newMethods, 0,
                methodsLength);
        setMethods(newMethods);
    }
}
