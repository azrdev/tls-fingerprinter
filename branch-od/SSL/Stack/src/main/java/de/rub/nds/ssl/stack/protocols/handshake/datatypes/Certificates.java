package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Certificates part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 25, 2011
 */
public final class Certificates extends APubliclySerializable {

    /**
     * Default list size.
     */
    private static final int DEFAULT_LIST_SIZE = 3;
    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 3;
    /**
     * Minimum length of the encoded form.
     */
    public final static int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * List of all certificates of this object.
     */
    private ASN1Certificate[] certificates;

    /**
     * Initializes a Certificates object as defined in RFC-2246.
     */
    public Certificates() {
        certificates = new ASN1Certificate[0];
    }

    /**
     * Initializes a Certificates object as defined in RFC-2246.
     *
     * @param message Certificates in encoded form
     */
    public Certificates(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the Certificates of this message.
     *
     * @return The Certificates of this message
     */
    public ASN1Certificate[] getCertificates() {
        // deep copy
        ASN1Certificate[] tmp = new ASN1Certificate[certificates.length];
        System.arraycopy(certificates, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the Certificates of this message.
     *
     * @param certificates The Certificates to be used for this message
     */
    public final void setCertificates(
            final ASN1Certificate[] certificates) {
        if (certificates == null) {
            throw new IllegalArgumentException(
                    "Certificates must not be null!");
        }

        this.certificates = new ASN1Certificate[certificates.length];
        // refill, deep copy
        System.arraycopy(certificates, 0, this.certificates, 0,
                certificates.length);
    }

    /**
     * Set the Certificates of this message.
     *
     * @param certificates The Certificates to be used for this message
     */
    public final void setCertificates(
            final List<ASN1Certificate> certificates) {
        if (certificates == null) {
            throw new IllegalArgumentException(
                    "Certificates must not be null!");
        }

        setCertificates(
                certificates.toArray(new ASN1Certificate[certificates.size()]));
    }

    /**
     * {@inheritDoc} CipherSuites representation 3 + x bytes Certificate.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        int certificatesLength = 0;
        byte[][] encCertificates = new byte[certificates.length][];
        byte[] certificatesMessage;
        byte[] tmpBytes = null;


        // build certificates
        for (ASN1Certificate cert : certificates) {
            // already deep copied
            encCertificates[pointer] = cert.encode(false);
            certificatesLength += encCertificates[pointer].length;
            pointer++;
        }

        pointer = 0;
        certificatesMessage = new byte[certificatesLength
                + LENGTH_LENGTH_FIELD];

        // 1. length
        tmpBytes = buildLength(certificatesLength, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmpBytes, 0, certificatesMessage, pointer,
                LENGTH_LENGTH_FIELD);
        pointer += tmpBytes.length;

        // 2. certificates
        for (byte[] tmpCert : encCertificates) {
            System.arraycopy(tmpCert, 0, certificatesMessage, pointer,
                    tmpCert.length);
            pointer += tmpCert.length;
        }

        return certificatesMessage;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        int pointer = 0;
        int extractedLength = 0;
        byte[] tmpBytes;
        final List<ASN1Certificate> tmpCerts =
                new ArrayList<ASN1Certificate>(DEFAULT_LIST_SIZE);

        // deep copy
        final byte[] certificatesCopy = new byte[message.length];
        System.arraycopy(message, 0, certificatesCopy, 0,
                certificatesCopy.length);

        // check size
        if (certificatesCopy.length < LENGTH_LENGTH_FIELD) {
            throw new IllegalArgumentException(
                    "Certificates record too short.");
        }
        extractedLength =
                extractLength(certificatesCopy, 0, LENGTH_LENGTH_FIELD);
        if (certificatesCopy.length - LENGTH_LENGTH_FIELD != extractedLength) {
            throw new IllegalArgumentException(
                    "Certificates record length invalid.");
        }
        pointer += LENGTH_LENGTH_FIELD;

        // extract Certificates
        while (pointer < certificatesCopy.length) {
            extractedLength = extractLength(certificatesCopy, pointer,
                    LENGTH_MINIMUM_ENCODED);
            tmpBytes = new byte[extractedLength
                    + ASN1Certificate.LENGTH_MINIMUM_ENCODED];
            System.arraycopy(certificatesCopy, pointer, tmpBytes, 0,
                    tmpBytes.length);

            tmpCerts.add(new ASN1Certificate(tmpBytes));
            pointer += tmpBytes.length;
        }
        setCertificates(tmpCerts);
    }
    
    public String toString() {
    	StringBuffer sb = new StringBuffer();
    	sb.append("Certificates:\n");
    	for (int i = 0; i < certificates.length; i++) {
    		sb.append("Certificate " + i + ":\n");
			sb.append(certificates[i].toString() + "\n");
		}
    	sb.append("end of certificates");
    	return new String(sb);
    }
}
