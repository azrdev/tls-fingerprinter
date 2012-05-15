package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * RSA Parameters as defined in RFC-2246. The RSA modulus and exponent which are
 * send in a ServerKeyExchange message if "RSA_EXPORT" key exchange is chosen in
 * the cipher suite.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 28, 2012
 */
public class ServerRSAParams extends APubliclySerializable implements
        IExchangeKeys {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * RSA modulus.
     */
    private byte[] rsaModulus = new byte[0];
    /**
     * RSA exponent.
     */
    private byte[] rsaExponent = new byte[0];

    /**
     * Initializes a ServerRSAParams part as defined in RFC 2246.
     *
     * @param message ServerRSAParams part in encoded form
     */
    public ServerRSAParams(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public final byte[] encode(final boolean chained) {
        int pointer = 0;
        byte[] length;
        byte[] serverRSAParams;
        serverRSAParams = new byte[LENGTH_LENGTH_FIELD + this.rsaModulus.length
                + LENGTH_LENGTH_FIELD + this.rsaExponent.length];

        /*
         * 2-byte length field for every parameter
         */
        length = buildLength(rsaModulus.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, serverRSAParams, pointer,
                LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        /*
         * add the RSA modulus parameter
         */
        System.arraycopy(this.rsaModulus, 0, serverRSAParams, pointer,
                this.rsaModulus.length);
        pointer += this.rsaModulus.length;

        /*
         * add the DH generator parameter
         */
        length = buildLength(rsaExponent.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, serverRSAParams, pointer,
                LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(this.rsaExponent, 0, serverRSAParams, pointer,
                this.rsaExponent.length);

        return serverRSAParams;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        int extractedLength;
        byte[] tmpBytes;
        // deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);

        int pointer = 0;
        // 1. extract the RSA modulus
        extractedLength = extractLength(paramCopy, 0, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setRsaModulus(tmpBytes);
        pointer += tmpBytes.length;

        // 2. extract the RSA exponent
        extractedLength = extractLength(paramCopy, pointer,
                   LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setRsaExponent(tmpBytes);

    }

    /**
     * Get the RSA modulus parameter.
     *
     * @return RSA modulus
     */
    public final byte[] getRsaModulus() {
        return rsaModulus.clone();
    }

    /**
     * Set the RSA modulus parameter.
     *
     * @param modulus RSA modulus
     */
    public final void setRsaModulus(final byte[] modulus) {
        this.rsaModulus = modulus.clone();
    }

    /**
     * Get the RSA exponent parameter.
     *
     * @return RSA exponent
     */
    public final byte[] getRsaExponent() {
        return rsaExponent.clone();
    }

    /**
     * Set the RSA exponent parameter.
     *
     * @param exponent RSA exponent
     */
    public final void setRsaExponent(final byte[] exponent) {
        this.rsaExponent = exponent.clone();
    }
}
