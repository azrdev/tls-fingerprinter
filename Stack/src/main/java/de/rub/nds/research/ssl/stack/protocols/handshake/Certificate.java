package de.rub.nds.research.ssl.stack.protocols.handshake;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.Certificates;

/**
 * Defines the Certificate message of SSL/TLS as defined in RFC 2246
 * 
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 25, 2011
 */
public final class Certificate extends AHandshakeRecord {

    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED =
            Certificates.LENGTH_MINIMUM_ENCODED;
    private Certificates certificates = new Certificates();

    /**
     * Initializes a Certificate message as defined in RFC 2246.
     * 
     * @param message Certificate message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public Certificate(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a Certificate message as defined in RFC 2246.
     * 
     * @param protocolVersion Protocol version of this message
     */
    public Certificate(final EProtocolVersion protocolVersion) {
        super(protocolVersion, EMessageType.CERTIFICATE);
    }

    /**
     * {@inheritDoc}
     *
     * Certificate representation
     *  3 + x bytes Certificates
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] encCertificates = certificates.encode(false);
        // putting the pieces together
        byte[] certificateMsg = new byte[LENGTH_MINIMUM_ENCODED +
                encCertificates.length];

        /*
         * Prepre Certificate message
         */
        // add certificates
        System.arraycopy(encCertificates, 0, certificateMsg, 0,
                encCertificates.length);
        
        super.setPayload(certificateMsg);
        return chained ? super.encode(true) : certificateMsg;        
    }

    /**
     * {@inheritDoc}
     */
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        int pointer;
        int extractedLength;

        if(chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        
        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length < Certificates.LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Certificate message too short.");
        }
        
        certificates = new Certificates(payloadCopy);
    }

    /**
     * Get the certificates of this message
     * @return Certificates
     */
    public Certificates getCertificates() {
        return new Certificates(certificates.encode(false));
    }
    
    /**
     * Set the certificates of this message
     * @param certificates Certificates to be set
     */
    public void setCertificates(final Certificates certificates) {
        this.certificates = new Certificates(certificates.encode(false));
    }
}
