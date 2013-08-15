package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;

/**
 * Client EC Diffie-Hellman public part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Aug 04, 2013
 */
public final class ClientECDHPublic extends APubliclySerializable
        implements IExchangeKeys {

    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = 0; // implicit case
    /**
     * Ephemeral ECDH public key (point).
     */
    private ECPoint ecdhYc;
    /**
     * Public value encoding.
     */
    private EPublicValueEncoding publicValueEncoding;

    /**
     * Public value encoding type.
     */
    private enum EPublicValueEncoding {

        /**
         * Implicit case - no contents (Fixed ECDH).
         */
        IMPLICIT,
        /**
         * Explicit case - EC point as content.
         */
        EXPLICIT;
    }

    /**
     * Initializes an Client ECDH Public part as defined in RFC 4492.
     */
    public ClientECDHPublic() {
    }

    /**
     * Initializes an Client ECDH Public part as defined in RFC 4492.
     *
     * @param message Client ECDH Public part in encoded form
     */
    public ClientECDHPublic(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the ECDH Yc value of this message.
     *
     * @return The ECDH Yc value of this message
     */
    public ECPoint getECDHYc() {
        ECPoint result;
        // deep copy
        result = new ECPoint(ecdhYc.encode(false));

        return result;
    }

    /**
     * Set the ECDH Yc value of this message part.
     *
     * @param ecdhYcValue The ECDH Yc value to be used for this message part
     */
    public void setECDHYc(final ECPoint ecdhYcValue) {
        if (ecdhYcValue == null) {
            throw new IllegalArgumentException("ECDH Yc value "
                    + "must not be null!");
        }

        // deep copy
        this.ecdhYc = new ECPoint(ecdhYcValue.encode(false));
    }

    /**
     * Is the public value included in this message?
     *
     * @return If the public value is included in this message.
     */
    public boolean isExplicitPublicValueEncoding() {
        boolean result = true;

        if (publicValueEncoding == EPublicValueEncoding.IMPLICIT) {
            result = false;
        }

        return result;
    }

    /**
     * Defines if the public value is explicitly included in this message or
     * implicitly contained in the certificate.
     *
     * @param explicit True if this message contains the public value (point)
     */
    public void setExplicitPublicValueEncoding(final boolean explicit) {
        if (explicit) {
            this.publicValueEncoding = EPublicValueEncoding.EXPLICIT;
        } else {
            this.publicValueEncoding = EPublicValueEncoding.IMPLICIT;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Chained parameter is ignored - no chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] ecdhPublic = new byte[0];

        if (isExplicitPublicValueEncoding()) {
            ecdhPublic = this.ecdhYc.encode(false);
        }

        return ecdhPublic;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        if (message.length == 0) {
            setExplicitPublicValueEncoding(false);
        } else {
            setExplicitPublicValueEncoding(true);
            setECDHYc(new ECPoint(message));
        }
    }
}
