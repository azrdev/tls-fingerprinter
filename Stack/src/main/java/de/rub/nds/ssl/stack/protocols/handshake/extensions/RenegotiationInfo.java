package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * RenegotiationInfo extension from RFC 5746
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class RenegotiationInfo extends AExtension {
    private static final int LENGTH_LENGTH_FIELD = 1;

    private byte[] renegotiatedConnection = new byte[0];

    /**
     * Initialize an empty extension object
     */
    public RenegotiationInfo() {
        setExtensionType(EExtensionType.RENEGOTIATION_INFO);
    }

    /**
     * Initialize an extension object from its encoded form
     */
    public RenegotiationInfo(byte[] encoded) {
        this(encoded, true);
    }

    /**
     * Initialize an extension object from its encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public RenegotiationInfo(byte[] encoded, boolean chained) {
        setExtensionType(EExtensionType.RENEGOTIATION_INFO);
        decode(encoded, chained);
    }

    public byte[] getRenegotiatedConnection() {
        return renegotiatedConnection;
    }

    public void setRenegotiatedConnection(byte[] renegotiatedConnection) {
        if(renegotiatedConnection == null) {
            throw new IllegalArgumentException(
                    "renegotiated_connection parameter must not be null");
        }

        this.renegotiatedConnection = Arrays.copyOf(renegotiatedConnection,
                renegotiatedConnection.length);
    }

    @Override
    public byte[] encode(boolean chained) {
        byte[] extensionBytes = new byte[LENGTH_LENGTH_FIELD +
                renegotiatedConnection.length];

        // 1. Length field
        byte[] length = buildLength(renegotiatedConnection.length, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, extensionBytes, 0, length.length);

        // 2. renegotiated_connection field
        System.arraycopy(renegotiatedConnection, 0, extensionBytes, LENGTH_LENGTH_FIELD,
                renegotiatedConnection.length);

        setExtensionData(extensionBytes);
        return super.encode(chained);
    }

    @Override
    public void decode(byte[] message, boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        byte[] raw = getExtensionData();
        int pointer = 0;

        if(raw.length < LENGTH_LENGTH_FIELD) {
            throw new IllegalArgumentException("Renegotiation info too short.");
        }

        // 1. Length field
        int extractedLength = extractLength(raw, pointer, LENGTH_LENGTH_FIELD);
        pointer += LENGTH_LENGTH_FIELD;
        if(pointer + extractedLength != raw.length) {
            throw new IllegalArgumentException(
                    "Length field of renegotiation info invalid");
        }

        // 2. renegotiated_connection field
        byte[] tmp = new byte[extractedLength];
        System.arraycopy(raw, pointer, tmp, 0, tmp.length);
        setRenegotiatedConnection(tmp);
    }
}
