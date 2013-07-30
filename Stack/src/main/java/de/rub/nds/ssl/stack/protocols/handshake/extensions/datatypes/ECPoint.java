package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;

/**
 * ECPoint part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2013
 */
public final class ECPoint extends APubliclySerializable
        implements IExchangeKeys {

    /**
     * Length of the point parameter.
     */
    private static final int LENGTH_LENGTH_FIELD = 1;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD+1;
    /**
     * ANSI X9.62 encoded EC coefficient a.
     */
    private byte[] point;
    
    
    /**
     * Initializes an EC Point part as defined in RFC 4492. 
     */
    public ECPoint() {
        
    }

    /**
     * Initializes an EC Point part as defined in RFC 4492. 
     *
     * @param message EC Point part in encoded form
     */
    public ECPoint(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the point value of this message.
     *
     * @return The point value of this message
     */
    public byte[] getPoint() {
        // deep copy
        byte[] tmp = new byte[point.length];
        System.arraycopy(point, 0, tmp, 0, tmp.length);

        return tmp;
    }
    
    /**
     * Set the point value of this message part. 
     *
     * @param point The point value to be used for this message part
     */
    public void setPoint(final byte[] point) {
        if (point == null) {
            throw new IllegalArgumentException("Point"
                    + "must not be null!");
        }

        // deep copy
        this.point = new byte[point.length];
        System.arraycopy(point, 0, this.point, 0, point.length);
    }

    /**
     * {@inheritDoc}
     *
     * ECCurve representation 1 byte a + 1 byte b.
     * Chained parameter is ignored - no chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        byte[] length = new byte[LENGTH_LENGTH_FIELD];
        byte[] ecPoint;
        ecPoint = new byte[LENGTH_LENGTH_FIELD + this.point.length];

        /*
         * 1-byte length field for point parameter
         */
        length = buildLength(point.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, ecPoint, pointer, length.length);
        pointer += length.length;
        /*
         * add the DH point
         */
        System.arraycopy(this.point, 0, ecPoint, pointer, this.point.length);
        pointer += this.point.length;

        return ecPoint;
    }

    /**
     * {@inheritDoc}
     * 
     * Chained parameter is ignored - no chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        int extractedLength;
        byte[] tmpBytes;
        // deep copy
        final byte[] ecPointCopy = new byte[message.length];
        System.arraycopy(message, 0, ecPointCopy, 0, ecPointCopy.length);

        int pointer = 0;
        // 1. extract the point
        extractedLength = extractLength(ecPointCopy, 0, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(ecPointCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setPoint(tmpBytes);
        pointer += tmpBytes.length;
    }

}
