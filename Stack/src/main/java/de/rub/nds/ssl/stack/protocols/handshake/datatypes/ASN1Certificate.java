package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;



import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * ASN.1 certificate message part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 25, 2011
 */
public final class ASN1Certificate extends APubliclySerializable {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 3;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * ASN.1 certificate.
     */
    private byte[] certificate = new byte[0];

    /**
     * Initializes an ASN.1 certificate object as defined in RFC-2246. Set by
     * default to 0x0!
     */
    public ASN1Certificate() {
    }

    /**
     * Initializes an ASN.1 certificate object as defined in RFC-2246.
     *
     * @param message ASN.1 certificate in encoded form
     */
    public ASN1Certificate(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the ASN.1 certificate of this message.
     *
     * @return The ASN.1 certificate of this message
     */
    public byte[] getCertificate() {
        // deep copy
        byte[] tmp = new byte[certificate.length];
        System.arraycopy(certificate, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the ASN.1 certificate of this message.
     *
     * @param certificate The ASN.1 certificate to be used for this message
     */
    public final void setCertificate(final byte[] certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException(
                    "ASN.1 certificate must not be null!");
        }

        // deep copy
        this.certificate = new byte[certificate.length];
        System.arraycopy(certificate, 0, this.certificate,
                0, certificate.length);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        final byte[] certificateBytes =
                new byte[certificate.length + LENGTH_LENGTH_FIELD];

        byte[] tmpBytes = buildLength(certificate.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmpBytes, 0, certificateBytes, 0, tmpBytes.length);
        System.arraycopy(certificate, 0, certificateBytes, LENGTH_LENGTH_FIELD,
                certificate.length);

        return certificateBytes;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        final int extractedLength;
        final byte[] tmpBytes;
        // deep copy
        final byte[] certificateCopy = new byte[message.length];
        System.arraycopy(message, 0, certificateCopy,
                0, certificateCopy.length);

        // check size
        if (certificateCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "ASN.1 certificate record too short.");
        }

        extractedLength = extractLength(certificateCopy,
                0, LENGTH_LENGTH_FIELD);
        tmpBytes = new byte[extractedLength];
        System.arraycopy(certificateCopy, LENGTH_LENGTH_FIELD, tmpBytes, 0,
                tmpBytes.length);
        setCertificate(tmpBytes);
    }
    
    public String toString() {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			String s = cf.generateCertificate(new ByteArrayInputStream(certificate)).toString();
			return s;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

    }
    
    
}
