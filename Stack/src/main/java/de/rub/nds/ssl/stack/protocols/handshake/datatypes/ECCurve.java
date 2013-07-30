package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * ECCurve part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2013
 */
public final class ECCurve extends APubliclySerializable
        implements IExchangeKeys {

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
    private byte a;
    /**
     * ANSI X9.62 encoded EC coefficient a.
     */
    private byte b;
    
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
    public byte getA() {
        return this.a;
    }
    
    /**
     * Get the b value of this message.
     *
     * @return The b value of this message
     */
    public byte getB() {
        return this.b;
    }

    /**
     * Set the a value of this message part. 
     *
     * @param a The a value to be used for this message part
     */
    public void setA(final byte a) {
        this.a = a;
    }
    
    /**
     * Set the b value of this message part. 
     *
     * @param b The b value to be used for this message part
     */
    public void setB(final byte b) {
        this.b = b;
    }

    /**
     * {@inheritDoc}
     *
     * ECCurve representation 1 byte a + 1 byte b.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;

        // putting the pieces together
        byte[] ecCurve = new byte[LENGTH_MINIMUM_ENCODED];

        // add a
        System.arraycopy(a, 0, ecCurve, pointer, LENGTH_A);
        pointer += LENGTH_A;
        
        // add b
        System.arraycopy(b, 0, ecCurve, pointer, LENGTH_B);
        pointer += LENGTH_B;

        return ecCurve;
    }

    /**
     * {@inheritDoc}
     */
    public void decode(final byte[] message, final boolean chained) {
        byte[] ecCurve = new byte[message.length];
        
        // deep copy
        System.arraycopy(message, 0, ecCurve, 0, ecCurve.length);

        // 1. extract a
        setA(message[0]);

        // 2. extract b
        setB(message[1]);
    }

}
