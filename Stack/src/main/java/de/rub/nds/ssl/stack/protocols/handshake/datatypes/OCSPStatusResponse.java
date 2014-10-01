package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

/**
 * OCSP Status Response as in RFC 6066 section 8
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class OCSPStatusResponse extends ACertificateStatusResponse {
    private static Logger logger = Logger.getLogger(OCSPStatusResponse.class);

    /**
     * Length of the length field of the OCSPResponse
     */
    private static final int LENGTH_OCSP_RESPONSE_LENGTH = 3;

    private static final int LENGTH_MINIMUM_ENCODED = LENGTH_OCSP_RESPONSE_LENGTH;

    /**
     * OCSP response bytes as in RFC 6066.
     *
     * <blockquote>An "ocsp_response" contains a complete, DER-encoded OCSP response
     * (using the ASN.1 type OCSPResponse defined in [RFC2560]).</blockquote>
     *
     * TODO: decode OCSP response
     */
    private byte[] ocspResponse = new byte[0];

    /**
     * Initialize an OCSPStatusResponse with empty responderIdList and requestExtensions.
     */
    public OCSPStatusResponse() {
        setType(ECertificateStatusType.OCSP);
    }

    /**
     * Initialize from encoded message
     */
    public OCSPStatusResponse(byte[] encoded) {
        setType(ECertificateStatusType.OCSP);
        decode(encoded, true);
    }

    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    public void setOcspResponse(byte[] ocspResponse) {
        Objects.requireNonNull(ocspResponse);

        this.ocspResponse = ocspResponse;
    }

    /**
     * @param chained <b>ignored</b>
     */
    @Override
    public byte[] encode(boolean chained) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            bytes.write(buildLength(ocspResponse.length, LENGTH_OCSP_RESPONSE_LENGTH));
            bytes.write(ocspResponse);
        } catch (IOException e) {
            logger.warn("ByteArrayOutputStream throws but should never: " + e);
        }

        return bytes.toByteArray();
    }

    /**
     * @param chained <b>ignored</b>
     */
    @Override
    public void decode(final byte[] message, boolean chained) {
        byte[] messageCopy = Arrays.copyOf(message, message.length);
        int pointer = 0;

        if(LENGTH_MINIMUM_ENCODED > messageCopy.length)
            throw new IllegalArgumentException("OCSPStatusResponse too short");

        // request_extensions
        final int responseLength = extractLength(messageCopy, pointer,
                LENGTH_OCSP_RESPONSE_LENGTH);
        pointer += LENGTH_OCSP_RESPONSE_LENGTH;
        if(pointer + responseLength > messageCopy.length)
            throw new IllegalArgumentException("OCSP Response length field invalid");

        byte[] tmp = Arrays.copyOfRange(messageCopy, pointer,
                pointer + responseLength);
        setOcspResponse(tmp);
    }
}
