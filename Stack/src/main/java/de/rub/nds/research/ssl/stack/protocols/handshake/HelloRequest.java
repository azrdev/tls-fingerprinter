package de.rub.nds.research.ssl.stack.protocols.handshake;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines the HelloRequest message of SSL/TLS as defined in RFC 2246
 * 
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 25, 2011
 */
public final class HelloRequest extends AHandshakeRecord {

    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = 0;

    /**
     * Initializes a HelloRequest message as defined in RFC 2246.
     * 
     * @param message HelloRequest message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public HelloRequest(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a HelloRequest message as defined in RFC 2246.
     * 
     * @param protocolVersion Protocol version of this message
     */
    public HelloRequest(final EProtocolVersion protocolVersion) {
        super(protocolVersion, EMessageType.HELLO_REQUEST);
    }

    /**
     * Set the protocol version at the record layer level. 
     * 
     * @param version Protocol version for the record Layer
     */
    public void setRecordLayerProtocolVersion(final EProtocolVersion version) {
        this.setProtocolVersion(version);
    }

    /**
     * Set the protocol version at the record layer level. 
     * 
     * @param version Protocol version for the record Layer
     */
    public void setRecordLayerProtocolVersion(final byte[] version) {
        this.setProtocolVersion(version);
    }

    /**
     * {@inheritDoc}
     *
     * HelloRequest representation
     *          0 bytes
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] helloRequest = new byte[0];
        
        super.setPayload(helloRequest);
        return chained ? super.encode(true) : helloRequest;
    }

    /**
     * {@inheritDoc}
     */
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;

        if(chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        
        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length != LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "HelloRequest must exactly be 0 bytes.");
        }
    }
}
