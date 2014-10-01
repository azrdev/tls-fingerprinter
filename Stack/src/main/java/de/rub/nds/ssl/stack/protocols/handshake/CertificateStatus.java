package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ACertificateStatusResponse;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ECertificateStatusType;

import java.util.Arrays;
import java.util.Objects;

/**
 * Defines the Certificate Status message as defined in RFC 6066
 *
 * @author jBiegert azrdev@qrdn.de
 */
public final class CertificateStatus extends AHandshakeRecord {

    /**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = ECertificateStatusType.LENGTH_ENCODED;

    private ECertificateStatusType certificateStatusType;
    private ACertificateStatusResponse certificateStatusResponse;

    /**
     * Initializes a Certificate Status message as defined in RFC 6066.
     *
     * @param message Message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public CertificateStatus(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();

        this.setMessageType(EMessageType.CERTIFICATE_STATUS);
        this.decode(message, chained);
    }

    /**
     * Initializes an empty Certificate message as defined in RFC 6066.
     * <br>
     * <b>NOTE</b>: The certificateStatusResponse must be set != null before calling
     * encode(), or this will generate an invalid message
     *
     * @param protocolVersion Protocol version of this message
     */
    public CertificateStatus(final EProtocolVersion protocolVersion) {
        super(protocolVersion, EMessageType.CERTIFICATE_STATUS);
    }

    /**
     * {@inheritDoc}
     *
     * Certificate representation 3 + x bytes Certificates
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] responseBytes = new byte[0];
        if(certificateStatusResponse != null)
            responseBytes = certificateStatusResponse.encode(true);

        int pointer = 0;
        byte[] bytes = new byte[ECertificateStatusType.LENGTH_ENCODED +
                responseBytes.length];

        bytes[pointer] = certificateStatusType.getId();
        pointer += ECertificateStatusType.LENGTH_ENCODED;

        System.arraycopy(responseBytes, 0, bytes, pointer, bytes.length - pointer);

        super.setPayload(bytes);
        return chained ? super.encode(true) : bytes;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();
        int pointer = 0;

        // check size
        if (pointer + LENGTH_MINIMUM_ENCODED > payloadCopy.length) {
            throw new IllegalArgumentException("CertificateStatus message too short.");
        }

        // get the status_type
        setCertificateStatusType(payloadCopy[pointer]);
        pointer += ECertificateStatusType.LENGTH_ENCODED;

        // get the response - give it all remaining bytes, we don't know about the length
        byte[] tmp = Arrays.copyOfRange(payloadCopy, pointer, payloadCopy.length);
        setCertificateStatusResponse(certificateStatusType.getResponse(tmp));
    }

    public ECertificateStatusType getCertificateStatusType() {
        return certificateStatusType;
    }

    public void setCertificateStatusType(final byte id) {
        this.certificateStatusType = ECertificateStatusType.getCertificateStatusType(id);
    }

    public void setCertificateStatusType(ECertificateStatusType certificateStatusType) {
        Objects.requireNonNull(certificateStatusType);

        this.certificateStatusType = certificateStatusType;
    }

    public ACertificateStatusResponse getCertificateStatusResponse() {
        return certificateStatusResponse;
    }

    public void setCertificateStatusResponse(ACertificateStatusResponse certificateStatusResponse) {
        Objects.requireNonNull(certificateStatusResponse);

        this.certificateStatusResponse = certificateStatusResponse;
    }
}
