package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * ECCurve part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2013
 */
public final class ECCurve extends APubliclySerializable {

    /**
     * Length of the a parameter.
     */
    private static final int LENGTH_A = 1;
    /**
     * Length of the b parameter.
     */
    private static final int LENGTH_B = 1;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_A + LENGTH_B;
    /**
     * ANSI X9.62 encoded EC coefficient a.
     */
    private byte[] a;
    /**
     * ANSI X9.62 encoded EC coefficient a.
     */
    private byte[] b;

    /**
     * Initializes an EC Curve part as defined in RFC 4492.
     */
    public ECCurve() {
    }

    /**
     * Initializes an EC Curve part as defined in RFC 4492.
     *
     * @param message EC Curve part in encoded form
     */
    public ECCurve(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the a value of this message.
     *
     * @return The a value of this message
     */
    public byte[] getA() {
        // deep copy
        byte[] tmp = new byte[a.length];
        System.arraycopy(a, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the a value of this message part.
     *
     * @param a The a value to be used for this message part
     */
    public void setA(final byte[] a) {
        if (a == null) {
            throw new IllegalArgumentException("A value "
                    + "must not be null!");
        }

        // deep copy
        this.a = new byte[a.length];
        System.arraycopy(a, 0, this.a, 0, a.length);
    }

    /**
     * Get the b value of this message.
     *
     * @return The b value of this message
     */
    public byte[] getB() {
        // deep copy
        byte[] tmp = new byte[b.length];
        System.arraycopy(b, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the b value of this message part.
     *
     * @param b The b value to be used for this message part
     */
    public void setB(final byte[] b) {
        if (b == null) {
            throw new IllegalArgumentException("B value "
                    + "must not be null!");
        }

        // deep copy
        this.b = new byte[b.length];
        System.arraycopy(b, 0, this.b, 0, b.length);
    }

    /**
     * {@inheritDoc}
     *
     * ECCurve representation 1 byte a length + 1 byte a + 1 byte b length + 1
     * byte b. Chained parameter is ignored - no chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        byte[] length;
        byte[] ecCurve = new byte[LENGTH_A + this.a.length
                + LENGTH_B + this.b.length];

        /*
         * 1. add length field for a parameter
         */
        length = buildLength(a.length, LENGTH_A);
        System.arraycopy(length, 0, ecCurve, pointer, length.length);
        pointer += length.length;
        /*
         * 2. add the a parameter
         */
        System.arraycopy(this.a, 0, ecCurve, pointer, this.a.length);
        pointer += this.a.length;

        /*
         * 3. add length field for b parameter
         */
        length = buildLength(b.length, LENGTH_B);
        System.arraycopy(length, 0, ecCurve, pointer, length.length);
        pointer += length.length;
        /*
         * 4. add the b parameter
         */
        System.arraycopy(this.b, 0, ecCurve, pointer, this.b.length);
        pointer += this.b.length;

        return ecCurve;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        int extractedLength;
        byte[] tmpBytes;
        // deep copy
        final byte[] ecCurveCopy = new byte[message.length];
        System.arraycopy(message, 0, ecCurveCopy, 0, ecCurveCopy.length);

        int pointer = 0;
        // 1. extract a
        extractedLength = extractLength(ecCurveCopy, 0, LENGTH_A);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_A;
        System.arraycopy(ecCurveCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setA(tmpBytes);
        pointer += tmpBytes.length;

        // 2. extract b
        extractedLength = extractLength(ecCurveCopy, 0, LENGTH_B);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_B;
        System.arraycopy(ecCurveCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setB(tmpBytes);
        pointer += tmpBytes.length;
    }
}
