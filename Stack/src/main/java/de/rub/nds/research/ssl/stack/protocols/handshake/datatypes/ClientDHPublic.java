package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import java.security.SecureRandom;

/**
 * ClientDHPublic part - as defined in RFC-2246
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 17, 2012
 */
public final class ClientDHPublic extends APubliclySerializable
        implements IExchangeKeys {

    /**
     * Length of the dh_Yc parameter in the implicit case (refer to 7.4.7.2
     * Client Diffie-Hellman public valuein RFC 2246 )
     */
    private final static int LENGTH_DH_YC = 0;
    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = 0;
    /**
     * Length bytes
     */
    public final static int LENGTH_BYTES = 2;
    private byte[] dhyc = new byte[LENGTH_DH_YC];

    /**
     * Initializes a ClientDHPublic part as defined in RFC 2246. This will
     * create a message with implicit public value encoding.
     */
    public ClientDHPublic() {
        // implicit case: 0 bytes!
    }

    /**
     * Initializes a ClientDHPublic part as defined in RFC 2246.
     *
     * @param message ClientDHPublic part in encoded form
     */
    public ClientDHPublic(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the dh_yc value of this message.
     *
     * @return The dh_yc value of this message
     */
    public byte[] getDhyc() {
        // deep copy
        byte[] copy = new byte[LENGTH_DH_YC];
        System.arraycopy(dhyc, 0, copy, 0, LENGTH_DH_YC);
        return copy;
    }

    /**
     * Set the dh_yc value of this message part. A handled NULL parameter or an
     * aaray of length 0 will switch to implict public value encoding.
     *
     * @param dhyc The dh_yc value to be used for this message part
     */
    public void setDhyc(final byte[] dhyc) {
        // implicit case
        if (dhyc == null || dhyc.length == LENGTH_DH_YC) {
            this.dhyc = new byte[LENGTH_DH_YC];
        } else {
            // deep copy
            this.dhyc = new byte[dhyc.length];
            System.arraycopy(dhyc, 0, this.dhyc, 0, dhyc.length);
        }
    }

    /**
     * {@inheritDoc}
     *
     * ServerHello representation 2 bytes Protocol version 48 bytes Random value
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;

        byte[] length = new byte[LENGTH_BYTES];
        length = buildLength(dhyc.length, LENGTH_BYTES);

        // putting the pieces together
        byte[] clientDHPublic = new byte[LENGTH_BYTES + dhyc.length];

        // add length bytes
        System.arraycopy(length, 0, clientDHPublic, pointer, LENGTH_BYTES);
        pointer += LENGTH_BYTES;

        // add ClientDHPublic part
        System.arraycopy(dhyc, 0, clientDHPublic, pointer, dhyc.length);

        return clientDHPublic;
    }

    /**
     * {@inheritDoc}
     */
    public void decode(final byte[] message, final boolean chained) {
        byte[] dhPublic = new byte[message.length];
        byte[] tmpBytes;
        int length = 0;
        int pointer;

        // deep copy
        System.arraycopy(message, 0, dhPublic, 0, dhPublic.length);

        pointer = 0;

        // 1. extract length
        tmpBytes = new byte[LENGTH_BYTES];
        System.arraycopy(dhPublic, pointer, tmpBytes, 0, LENGTH_BYTES);
        pointer += LENGTH_BYTES;

        // 2. extract ciphertext
        length = extractLength(dhPublic, 0, 2);
        tmpBytes = new byte[length];
        System.arraycopy(dhPublic, pointer, tmpBytes, 0, length);
        setDhyc(tmpBytes);
    }
}
