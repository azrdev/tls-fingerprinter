package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * ServerDHParams part - as defined in RFC-2246.
 * Parameters to perform diffie-hellman, precisely the
 * prime modulus, the generator and the public value.
 * Parameter length is between 1 and 2^16.
 * @author  Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Apr 17, 2012
 */
public class ServerDHParams extends APubliclySerializable implements IExchangeKeys {
	
	/**
	 * Length of the length field.
	 */
	private static final int LENGTH_LENGTH_FIELD = 2;
	
	/**Prime modulus for DH.*/
	private byte[] dhp = new byte[0];
	/**Generator for DH.*/
	private byte[] dhg = new byte[0];
	/**Server's DH public value.*/
	private byte[] dhys = new byte[0];
	
	/**
     * Initializes a ServerDHParams part as defined in RFC 2246.
     * 
     * @param message ServerDHParams part in encoded form
     */
    public ServerDHParams(final byte[] message) {
        this.decode(message, false);
    }
    
    /**
     * {@inheritDoc}
     * 
     * Method parameter will be ignored - no support for chained encoding
     */
	@Override
	public byte[] encode(final boolean chained) {
		int pointer = 0;
		byte[] length = new byte [LENGTH_LENGTH_FIELD];
        byte[] serverDHParams;
        serverDHParams = new byte[LENGTH_LENGTH_FIELD + this.dhp.length
                                  + LENGTH_LENGTH_FIELD + this.dhg.length
                                  + LENGTH_LENGTH_FIELD + this.dhys.length];

        /*2-byte length field for every parameter*/
        length = buildLength(dhp.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, serverDHParams, pointer, LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        /*add the DH prime parameter*/
        System.arraycopy(this.dhp, 0, serverDHParams, pointer, this.dhp.length);
        pointer += this.dhp.length;
        
        /*add the DH generator parameter*/
        length = buildLength(dhg.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, serverDHParams, pointer, LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(this.dhg, 0, serverDHParams, pointer, this.dhg.length);
        pointer += this.dhg.length;
        
        /*add the DH public value parameter*/
        length = buildLength(dhys.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, serverDHParams, pointer, LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(this.dhys, 0, serverDHParams, pointer, this.dhys.length);
      
        return serverDHParams;
	}

	/**
     * {@inheritDoc}
     * 
     * Method parameter will be ignored - no support for chained encoding
     */
	@Override
	public void decode(final byte[] message, final boolean chained) {
		int extractedLength;
		byte[] tmpBytes;
		// deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);
        
        int pointer = 0;
        // 1. extract dh_p 
        extractedLength = extractLength(paramCopy, 0, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setDHPrime(tmpBytes);
        pointer += tmpBytes.length;
        
        // 2. extract dh_g
        extractedLength = extractLength(paramCopy, pointer, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setDHGenerator(tmpBytes);
        pointer += tmpBytes.length;
        
        // 3. extract dh_Ys 
        extractedLength = extractLength(paramCopy, pointer, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        pointer += LENGTH_LENGTH_FIELD;
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setDHPublicValue(tmpBytes);
	}
	
	/**
	 * Set prime modulus for DH.
	 * @param prime Prime modulus
	 */
	public final void setDHPrime(final byte [] prime) {
		this.dhp = prime;
	}
	
	/**
	 * Get prime modulus for DH.
	 * @return Prime modulus
	 */
	public final byte [] getDHPrime() {
		return this.dhp;
	}
	
	/**
	 * Set generator for DH.
	 * @param gen Generator
	 */
	public final void setDHGenerator(final byte [] gen) {
		this.dhg = gen;
	}
	
	/**
	 * Get generator for DH.
	 * @return DH generator
	 */
	public final byte [] getDHGenerator() {
		return this.dhg;
	}
	
	/**
	 * Set server's public value for DH.
	 * @param pubValue Server's public value
	 */
	public final void setDHPublicValue(final byte [] pubValue) {
		this.dhys = pubValue;
	}
	
	/**
	 * Get server's public value for DH.
	 * @return DH public value
	 */
	public final byte [] getDHPublicValue() {
		return this.dhys;
	}

}
