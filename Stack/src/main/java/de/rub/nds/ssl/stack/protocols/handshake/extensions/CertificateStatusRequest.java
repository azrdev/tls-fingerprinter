package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ACertificateStatusRequest;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ECertificateStatusType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.Objects;

/**
 * A CertificateStatusRequest hello extension as in RFC 6066
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class CertificateStatusRequest extends AExtension {

    public static final int LENGTH_MINIMUM_ENCODED =
            ECertificateStatusType.LENGTH_ENCODED;

    private ACertificateStatusRequest certificateStatusRequest;
    private ECertificateStatusType certificateStatusType;

    /**
     * Initialize an empty extension object
     */
    public CertificateStatusRequest() {
        setExtensionType(EExtensionType.STATUS_REQUEST);
    }

    /**
     * Initialize an extension object from encoded message
     */
    public CertificateStatusRequest(byte[] message) {
        this(message, true);
    }

    /**
     * Initialize an extension object from encoded message
     * @param chained Decode underlying frames
     */
    public CertificateStatusRequest(byte[] message, boolean chained) {
        setExtensionType(EExtensionType.STATUS_REQUEST);
        decode(message, chained);
    }

    /**
     * @return The contained CSR. null if the extension was empty.
     */
    public ACertificateStatusRequest getCertificateStatusRequest() {
        return certificateStatusRequest;
    }

    /**
     * Sets the contained CSR. If null, the extension will be empty.
     */
    public void setCertificateStatusRequest(ACertificateStatusRequest certificateStatusRequest) {
        this.certificateStatusRequest = certificateStatusRequest;
    }

    @Override
    public byte[] encode(boolean chained) {
        final byte[] encodedRequest = certificateStatusRequest == null ?
                new byte[0] : certificateStatusRequest.encode(true);

        int pointer = 0;
        byte[] bytes = new byte[ECertificateStatusType.LENGTH_ENCODED +
                encodedRequest.length];

        bytes[pointer] = getCertificateStatusType().getId();
        pointer += ECertificateStatusType.LENGTH_ENCODED;

        System.arraycopy(encodedRequest, 0, bytes, pointer, bytes.length - pointer);

        setExtensionData(bytes);
        return chained ? super.encode(chained) : bytes;
    }

    @Override
    public void decode(byte[] message, boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        int pointer = 0;
        final byte[] messageCopy = getExtensionData();

        if(messageCopy.length == 0) {
            setCertificateStatusRequest(null);
            return;
        }

        if(LENGTH_MINIMUM_ENCODED > messageCopy.length)
            throw new IllegalArgumentException("CertificateStatusRequest too short.");

        // 1. parse status_type
        setCertificateStatusType(messageCopy[pointer]);
        pointer += ECertificateStatusType.LENGTH_ENCODED;

        // 2. request
        byte[] tmp = new byte[messageCopy.length - pointer];
        System.arraycopy(messageCopy, pointer, tmp, 0, tmp.length);
        setCertificateStatusRequest(getCertificateStatusType().getRequest(tmp));
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
}
