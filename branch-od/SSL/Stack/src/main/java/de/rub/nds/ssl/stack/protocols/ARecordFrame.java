package de.rub.nds.ssl.stack.protocols;

import java.util.Arrays;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Record Layer for the SSL/TLS Protocol
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 *
 * Feb 05, 2014
 */
public abstract class ARecordFrame extends APubliclySerializable {

    /**
     * Length of the length field
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = EContentType.LENGTH_ENCODED
            + EProtocolVersion.LENGTH_ENCODED
            + LENGTH_LENGTH_FIELD;
    /**
     * Maximum payload size
     */
    private static int MAX_MESSAGE_SIZE = 1 << 14;
    /**
     * Content type of this record
     */
    private EContentType contentType = EContentType.ALERT;
    /**
     * Protocol version of this record
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Frame payload payload
     */
    private byte[] payload = new byte[]{};

    /**
     * Dummy constructor - used by the mandatory super() calls
     */
    protected ARecordFrame() {
        super();
    }
    
    
    public String toString() {
    	return  "ARecordFrame (" + this.getClass().getCanonicalName() + "):\n" +
    			"  contentType = " + this.contentType + "\n" +
    			"  protocolVersion = " + this.getProtocolVersion() + "\n" + 
    			"  length = " + this.getPayload().length;
    }

    /**
     * Initializes record frame as defined in RFC 2246
     *
     * @param type Content type
     * @param version Protocol version
     * @param message Protocol payload
     */
    protected ARecordFrame(final EContentType type,
            final EProtocolVersion version,
            final byte[] message) {
        this(type, version);

        // check payload size
        if (message.length >= MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException("Record frame too large.");
        }

        this.setPayload(message);
    }

    /**
     * Initializes record frame as defined in RFC 2246
     *
     * @param message Record frame in encoded form
     */
    protected ARecordFrame(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Initializes record frame as defined in RFC 2246
     *
     * @param type Content type
     * @param version Protocol version
     */
    protected ARecordFrame(final EContentType type,
            final EProtocolVersion version) {
        // check arguments
        if (this.contentType == null || this.protocolVersion == null
                || this.payload == null) {
            throw new IllegalArgumentException("Neither content type, protocol"
                    + " version nor protocol message must be null.");
        }

        this.setContentType(type);
        this.setProtocolVersion(version);
    }

    /**
     * @inheritDoc
     *
     * ARecordFrame representation 1 byte Content type 2 bytes Protocol version
     * 2 + x bytes Payload
     *
     * Method parameter will be ignored - no support for chained encoding
     */
    public byte[] encode(boolean chained) {
        int pointer;
        byte[] tmp;
        final byte[] payloadCopy = getPayload();
        byte[] recordFrame = new byte[EContentType.LENGTH_ENCODED
                + EProtocolVersion.LENGTH_ENCODED
                + LENGTH_LENGTH_FIELD
                + payloadCopy.length];

        pointer = 0;
        // 1. content type
        tmp = new byte[]{getContentType().getId()};
        System.arraycopy(tmp, 0, recordFrame, pointer, tmp.length);
        pointer += tmp.length;

        // 2. version
        tmp = getProtocolVersion().getId();
        System.arraycopy(tmp, 0, recordFrame, pointer, tmp.length);
        pointer += tmp.length;

        // 3. payload length
        tmp = buildLength(payloadCopy.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmp, 0, recordFrame, pointer, tmp.length);
        pointer += tmp.length;

        // 4. payload
        tmp = payloadCopy;
        System.arraycopy(tmp, 0, recordFrame, pointer, tmp.length);

        return recordFrame;
    }

    /**
     * @inheritDoc
     *
     * Method parameter will be ignored - no support for chained decoding
     */
    public void decode(final byte[] message, final boolean chained) {
        final byte[] messageCopy = new byte[message.length];
        byte[] tmpBytes;
        int pointer;
        int extractedLength;

        // deep copy 
        System.arraycopy(message, 0, messageCopy, 0, messageCopy.length);

        // check size
        if (messageCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Record frame too short.");
        }

        pointer = 0;
        // 1. content type
        tmpBytes = new byte[EContentType.LENGTH_ENCODED];
        System.arraycopy(messageCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setContentType(tmpBytes[0]);
        pointer += tmpBytes.length;

        // 2. protocol version
        tmpBytes = new byte[EProtocolVersion.LENGTH_ENCODED];
        System.arraycopy(messageCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setProtocolVersion(tmpBytes);
        pointer += tmpBytes.length;

        // 3. payload 
        extractedLength =
                extractLength(messageCopy, pointer, LENGTH_LENGTH_FIELD);
        if (pointer + extractedLength + LENGTH_LENGTH_FIELD
                != messageCopy.length) {
            throw new IllegalArgumentException("Record payload length invalid.");
        }
        pointer += LENGTH_LENGTH_FIELD;
        tmpBytes = new byte[extractedLength];
        System.arraycopy(messageCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setPayload(tmpBytes);
    }

    /**
     * Get the content type of this record frame.
     *
     * @return The content type of this record frame.
     */
    public EContentType getContentType() {
        // deep copy
        return EContentType.valueOf(this.contentType.name());
    }

    /**
     * Set the content type of this record frame.
     *
     * @param contentType The content type to be used for this record frame
     */
    protected final void setContentType(final EContentType contentType) {
        if (contentType == null) {
            throw new IllegalArgumentException("Content type must not be null!");
        }

        // deep copy
        this.contentType = EContentType.valueOf(contentType.name());
    }

    /**
     * Set the content type of this record frame.
     *
     * @param contentType The content type to be used for this record frame
     */
    protected final void setContentType(final byte contentType) {
        // deep copy
        this.contentType = EContentType.getContentType(contentType);
    }

    /**
     * Get the protocol version of this record frame.
     *
     * @return The protocol version of this record frame.
     */
    public EProtocolVersion getProtocolVersion() {
        // deep copy
        return EProtocolVersion.valueOf(this.protocolVersion.name());
    }

    /**
     * Set the protocol version of this record frame.
     *
     * @param version The protocol version to be used for this record frame
     */
    protected final void setProtocolVersion(final EProtocolVersion version) {
        if (protocolVersion == null) {
            throw new IllegalArgumentException(
                    "Protocol version must not be null!");
        }

        // deep copy
        this.protocolVersion = EProtocolVersion.valueOf(version.name());
    }

    /**
     * Set the protocol version of this record frame.
     *
     * @param version The protocol version to be used for this record frame
     */
    protected final void setProtocolVersion(final byte[] version) {
        this.protocolVersion = EProtocolVersion.getProtocolVersion(version);
    }

    /**
     * Get the payload of this record frame.
     *
     * @return The payload of this record frame.
     */
    public byte[] getPayload() {
        // deep copy
        byte[] tmp = new byte[payload.length];
        System.arraycopy(payload, 0, tmp, 0, tmp.length);

        return tmp;
    }
    
    /**
    * Get the entire message including the global header.
    *
    * @return The entire message including the global header of this record frame.
    */
    public byte[] getBytes(){
        byte[] tmp = new byte[payload.length + 5];
        tmp[0] = contentType.getId();
        System.arraycopy(getProtocolVersion().getId(), 0, tmp, 1, 2);       
        tmp[3] = (byte)((payload.length >> 8) & 0xFF);
        tmp[4] = (byte)(payload.length & 0xFF);
        System.arraycopy(payload, 0, tmp, 5, payload.length);
        return tmp;
    }    

    /**
     * Set the payload of this record frame.
     *
     * @param payload The payload to be used for this record frame
     */
    protected final void setPayload(final byte[] payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload must not be null!");
        }

        // deep copy
        this.payload = new byte[payload.length];
        System.arraycopy(payload, 0, this.payload, 0, this.payload.length);
    }
}
