package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Signed Certificate Timestamp extension as in RFC 6962.
 * <p>
 * Contains a List of Signed Certificate Timestamps (SCTs)
 * <p>
 * <b>NOTE</b>: the extension_data is empty in most cases
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SignedCertificateTimestamp extends AExtension {
    /**
     * Length of the Length field of the SCT List
     */
    private static final int LENGTH_LIST_LENGTH = 2;

    /**
     * Length of the Length field of one SCT
     */
    private static final int LENGTH_SCT_LENGTH = 2;

    /**
     * The list of (unparsed) SCTs in this extension.
     * TODO: parse SignedCertificateTimestamps
     */
    private List<byte[]> signedCertificateTimestampList = new ArrayList<>(0);

    public SignedCertificateTimestamp() {
        setExtensionType(EExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
    }

    public SignedCertificateTimestamp(byte[] message) {
        this(message, true);
    }

    public SignedCertificateTimestamp(byte[] message, boolean chained) {
        setExtensionType(EExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
        decode(message, true);
    }

    @Override
    public void decode(byte[] message, boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        final byte[] extensionData = getExtensionData();
        int pointer = 0;

        if(extensionData.length == 0) {
            return;
        }

        //TODO: test below code (SCT List parsing)

        // 1. List length field
        int extractedListLength = extractLength(extensionData, pointer,
                LENGTH_LIST_LENGTH);
        pointer += LENGTH_LIST_LENGTH;
        if(pointer + extractedListLength != extensionData.length) {
            throw new IllegalArgumentException("SCTList has wrong length field");
        }

        List<byte[]> sctList = new LinkedList<>();
        // 2. SCT List
        while(pointer < extensionData.length) {
            // 1. SCT Length
            int extractedLength = extractLength(extensionData, pointer,
                    LENGTH_SCT_LENGTH);
            pointer += LENGTH_SCT_LENGTH;
            if(pointer + extractedLength > extensionData.length) {
                throw new IllegalArgumentException("SCT length field invalid.");
            }

            // 2. SCT
            byte[] tmp = new byte[extractedLength];
            System.arraycopy(extensionData, pointer, tmp, 0, tmp.length);
            sctList.add(tmp);
        }

        setSignedCertificateTimestampList(sctList);
    }

    public List<byte[]> getSignedCertificateTimestampList() {
        return signedCertificateTimestampList;
    }

    public void setSignedCertificateTimestampList(List<byte[]> list) {
        if(list == null) {
            throw new IllegalArgumentException("SCT List must not be null");
        }

        this.signedCertificateTimestampList = new ArrayList<>(list);
    }
}
