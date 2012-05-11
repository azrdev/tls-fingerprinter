package de.rub.nds.research.ssl.stack.protocols.alert.datatypes;

import java.util.HashMap;
import java.util.Map;

/**
 * Alert description of an Alert message
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 *
 * Apr. 08, 2012
 */
public enum EAlertDescription {

    CLOSE_NOTIFY((byte) 0x00),
    UNEXPECTED_MESSAGE((byte) 0x0a),
    BAD_RECORD_MAC((byte) 0x14),
    DECRYPTION_FAILED((byte) 0x15),
    RECORD_OVERFLOW((byte) 0x16),
    DECOMPRESSION_FAILURE((byte) 0x1e),
    HANDSHAKE_FAILURE((byte) 0x28),
    BAD_CERTIFICATE((byte) 0x2a),
    UNSUPPORTED_CERTIFICATE((byte) 0x2b),
    CERTIFICATE_REVOKED((byte) 0x2c),
    CERTIFICATE_EXPIRED((byte) 0x2d),
    CERTIFICATE_UNKNOWN((byte) 0x2e),
    ILLEGAL_PARAMETER((byte) 0x2f),
    UNKNOWN_CA((byte) 0x30),
    ACCESS_DENIED((byte) 0x31),
    DECODE_ERROR((byte) 0x32),
    DECRYPT_ERROR((byte) 0x33),
    EXPORT_RESTRICTION((byte) 0x3c),
    PROTOCOL_VERSION((byte) 0x46),
    INSUFFICIENT_SECURITY((byte) 0x47),
    INTERNAL_ERROR((byte) 0x50),
    USER_CANCELED((byte) 0x5a),
    NO_RENEGOTIATION((byte) 0x64);
    private byte desc;
    final private static Map<Integer, EAlertDescription> ID_MAP = new HashMap<Integer, EAlertDescription>();

    static {
        byte id;
        for (EAlertDescription tmp : EAlertDescription.values()) {
            id = tmp.getAlertDescriptionId();
            ID_MAP.put((int) id, tmp);
        }
    }

    EAlertDescription(final byte desc) {
        this.desc = desc;
    }

    /**
     * Get the byte-value of the alert description
     *
     * @return byte-value of the alert description
     */
    public byte getAlertDescriptionId() {
        return this.desc;
    }

    /**
     * Get the alert description
     *
     * @param desc Byte value of the alert description
     * @return Alert description
     */
    public static EAlertDescription getAlertDescription(byte desc) {
        return ID_MAP.get((int) desc);
    }
}
