package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EBulkCipherAlgorithm;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines all Handshake Messages of SSL/TLS
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 14, 2011
 */
abstract public class AHandshakeRecord extends ARecordFrame {

    /**
     * Length of the length field
     */
    private static final int LENGTH_LENGTH_FIELD = 3;
    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED =
            EMessageType.LENGTH_ENCODED + LENGTH_LENGTH_FIELD;
    /**
     * The message type of this handshake record
     */
    private EMessageType messageType = null;

    /**
     * Dummy constructor - used by the mandatory super() calls
     */
    protected AHandshakeRecord() {
        super();
        /*
         * fixes issues when chained decoding is not used (content type remains
         * unset in these case
         */
        this.setContentType(EContentType.HANDSHAKE);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param version Protocol version of this handshake message
     * @param message Encoded handshake message
     * @param type Message type of this handshake message
     */
    protected AHandshakeRecord(final EProtocolVersion version,
            final byte[] message, final EMessageType type) {
        super(EContentType.HANDSHAKE, version, message);
        this.setMessageType(type);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param message Encoded handshake message
     * @param chained Decode single or chained with underlying frames
     */
    protected AHandshakeRecord(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param version Protocol version
     * @param type Message type
     */
    protected AHandshakeRecord(final EProtocolVersion version,
            final EMessageType type) {
        super(EContentType.HANDSHAKE, version);
        this.setMessageType(type);
    }

    /**
     * {@inheritDoc}
     *
     * AHandshakeRecord representation 1 byte Message type 3 + x bytes Payload
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer;
        byte[] tmp;
        final byte[] payloadCopy = getPayload();
        byte[] handshakeRecord = new byte[EMessageType.LENGTH_ENCODED
                + LENGTH_LENGTH_FIELD
                + payloadCopy.length];

        pointer = 0;
        // 1. message type
        tmp = new byte[]{this.getMessageType().getId()};
        System.arraycopy(tmp, 0, handshakeRecord, pointer, tmp.length);
        pointer += tmp.length;

        // 2. payload length
        tmp = buildLength(payloadCopy.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmp, 0, handshakeRecord, pointer, tmp.length);
        pointer += tmp.length;

        // 3. payload
        tmp = payloadCopy;
        System.arraycopy(tmp, 0, handshakeRecord, pointer, tmp.length);

        super.setPayload(handshakeRecord);
        return chained ? super.encode(true) : handshakeRecord;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        final byte[] payloadCopy;
        byte[] tmpBytes;
        int pointer;
        int extractedLength;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Handshake record too short.");
        }

        pointer = 0;
        // 1. message type
        tmpBytes = new byte[EMessageType.LENGTH_ENCODED];
        System.arraycopy(payloadCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setMessageType(tmpBytes[0]);
        pointer += tmpBytes.length;

        // 2. payload 
        extractedLength =
                extractLength(payloadCopy, pointer, LENGTH_LENGTH_FIELD);
        if (pointer + extractedLength + LENGTH_LENGTH_FIELD
                > payloadCopy.length) {
            throw new IllegalArgumentException(
                    "Handshake record payload length invalid.");
        }
        pointer += LENGTH_LENGTH_FIELD;
        tmpBytes = new byte[extractedLength];
        System.arraycopy(payloadCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setPayload(tmpBytes);
    }
    
    public String toString() {
    	return super.toString() + "\n" +
    			"  messageType = " + this.getMessageType();
    }

    /**
     * Get the message type of this handshake record.
     *
     * @return The message type of this handshake record.
     */
    public EMessageType getMessageType() {
        // deep copy
        return EMessageType.valueOf(this.messageType.name());
    }

    /**
     * Set the message Type of this handshake record.
     *
     * @param messageType The message type to be used for this handshake record
     */
    protected final void setMessageType(final EMessageType messageType) {
        if (messageType == null) {
            throw new IllegalArgumentException("Message type must not be null!");
        }

        this.messageType = EMessageType.valueOf(messageType.name());
    }

    /**
     * Set the message Type of this handshake record.
     *
     * @param messageType The message type to be used for this handshake record
     */
    protected final void setMessageType(final byte messageType) {
        this.messageType = EMessageType.getMessageType(messageType);
    }
}
