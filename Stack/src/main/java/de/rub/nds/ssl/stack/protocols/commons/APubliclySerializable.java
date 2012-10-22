package de.rub.nds.ssl.stack.protocols.commons;

/**
 * Interface for all publicly serializable messages, message parts or record
 * frames.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 15, 2011
 */
public abstract class APubliclySerializable {

    /**
     * Encodes this object.
     *
     * @param chained Encode single or chained with underlying frames as valid
     * record layer frame
     * @return Encoded form of this object as specified in RFC-2246
     */
    public abstract byte[] encode(boolean chained);

    /**
     * Decodes a given byte array into a valid object if possible.
     *
     * @param message Byte representation of the message
     * @param chained Decode single or chained with underlying frames
     */
    public abstract void decode(byte[] message, boolean chained);

    /**
     * Extracts the length field out of a given byte array.
     *
     * @param bytes Byte array which contains the length information
     * @param offset Start in the array of the length field?
     * @param length Number of bytes forming together the length field
     *
     * @return Extracted length
     */
    protected int extractLength(final byte[] bytes, final int offset,
            final int length) {
        int result = 0;

        for (int i = 0; i < length; i++) {
            result |= (bytes[offset + i] & 0xff) << ((length - i - 1) * 8);
        }

        return result;
    }

    /**
     * Builds a length field over a given number of bytes.
     *
     * @param length Length value
     * @param bytes Number of bytes for the length value
     *
     * @return Byte array representation of the length
     */
    protected byte[] buildLength(final int length, final int bytes) {
        byte[] result = new byte[bytes];

        for (int i = 0; i < bytes; i++) {
            result[bytes - 1 - i] = ((Integer) (length >> (8 * i))).byteValue();
        }

        return result;
    }
    
    /**
     * Builds the String representation of the current object.
     * @return Current object in String representation
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer(50);
    	byte[] encoded = this.encode(true);
    	sb.append("APubliclySerializeable (");
        sb.append(this.getClass().getCanonicalName());
        sb.append("): ");
    	for (int i = 0; i < encoded.length-1; i++) {
    		sb.append(Integer.toHexString(encoded[i]&0xff));
    		sb.append(" ");
    	}
    	sb.append(Integer.toHexString(encoded[encoded.length-1]&0xff));
    	return new String(sb);
    }
}
