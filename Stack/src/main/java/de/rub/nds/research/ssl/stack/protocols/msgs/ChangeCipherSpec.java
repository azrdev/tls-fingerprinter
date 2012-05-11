package de.rub.nds.research.ssl.stack.protocols.msgs;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines the ChangeCipherSpec message of SSL/TLS as defined in RFC 2246
 * 
 * @author  Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Feb 15, 2012
 */
public final class ChangeCipherSpec extends ARecordFrame {
	
	private byte [] oneByte = null;
	
	/**
     * Initializes a ChangeCipherSpec message as defined in RFC 2246.
     * @param message ChangeCipherSpec message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public ChangeCipherSpec(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }
	
	/**
     * Initializes a ChangeCipherSpec as defined in RFC 2246
     * 
     * @param version Protocol version
     */
    public ChangeCipherSpec(final EProtocolVersion version) {
        super(EContentType.CHANGE_CIPHER_SPEC, version);
        this.oneByte = new byte[]{0x01};
    }
	
	 /**
     * {@inheritDoc}
     * ChangeCipherSpec message with a 1-byte payload
     */
    @Override
    public byte[] encode(boolean chained) {       
    	super.setPayload(this.oneByte);
        return super.encode(true);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
    	byte[] tmpBytes;
        byte[] payloadCopy;

        if(chained){
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        
        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length > 1 || payloadCopy.length==0) {
            throw new 
                    IllegalArgumentException("Unvalid ChangeCipherSpec message");
        }
        
        // extract byte 
        tmpBytes = new byte[1];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        this.oneByte=tmpBytes;

    }
    
    /**Set the payload of the record.
     * @param oneByte The Payload
     */
    public void setContent(byte [] oneByte){
    	this.oneByte=oneByte.clone();
    }
	

}
