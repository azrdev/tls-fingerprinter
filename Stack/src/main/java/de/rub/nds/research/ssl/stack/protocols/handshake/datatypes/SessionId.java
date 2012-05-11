package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * Session id message part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 24, 2011
 */
public final class SessionId extends APubliclySerializable {

    /**
     * Length of the length field
     */
    private static final int LENGTH_LENGTH_FIELD = 1;
    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * Session id
     */
    private byte[] id = new byte[0];

    /**
     * Initializes a session id object as defined in RFC-2246. Set by default to
     * 0x0!
     */
    public SessionId() {
    }

    /**
     * Initializes a session id object as defined in RFC-2246.
     *
     * @param message Session id in encoded form
     */
    public SessionId(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the session id of this message.
     *
     * @return The session id of this message
     */
    public byte[] getId() {
        // deep copy
        byte[] tmp = new byte[id.length];
        System.arraycopy(id, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the session id of this message.
     *
     * @param id The session id to be used for this message
     */
    public final void setId(final byte[] id) {
        if (id == null) {
            throw new IllegalArgumentException("Session id must not be null!");
        }

        // deep copy
        this.id = new byte[id.length];
        System.arraycopy(id, 0, this.id, 0, id.length);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding
     */
    @Override
    public byte[] encode(boolean chained) {
        byte[] tmp = new byte[id.length + LENGTH_LENGTH_FIELD];
        tmp[0] = ((Integer) id.length).byteValue();
        System.arraycopy(id, 0, tmp, LENGTH_LENGTH_FIELD, id.length);

        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding
     */
    public void decode(final byte[] message, final boolean chained) {
        final int extractLength;
        final byte[] tmpBytes;
        // deep copy
        final byte[] idCopy = new byte[message.length];
        System.arraycopy(message, 0, idCopy, 0, idCopy.length);

        // check size
        if (idCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Session id record too short.");
        }

        extractLength = extractLength(idCopy, 0, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractLength];
        System.arraycopy(idCopy, LENGTH_LENGTH_FIELD, tmpBytes, 0,
                tmpBytes.length);
        setId(tmpBytes);
    }
}
