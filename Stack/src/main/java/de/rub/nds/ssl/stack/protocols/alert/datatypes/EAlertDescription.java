package de.rub.nds.ssl.stack.protocols.alert.datatypes;

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
    /**
     * reserved
     */
    NO_CERTIFICATE((byte) 0x29),
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

    /**
     * reserved
     */
    EXPORT_RESTRICTION((byte) 0x3c),

    PROTOCOL_VERSION((byte) 0x46),
    INSUFFICIENT_SECURITY((byte) 0x47),

    INTERNAL_ERROR((byte) 0x50),

    USER_CANCELED((byte) 0x5a),

    NO_RENEGOTIATION((byte) 0x64),

    UNSUPPORTED_EXTENSION((byte) 0x6E),
    CERTIFICATE_UNOBTAINABLE((byte) 0x6F),
    UNRECOGNIZED_NAME((byte) 0x70),
    BAD_CERTIFICATE_STATUS_RESPONSE((byte) 0x71),
    BAD_CERTIFICATE_HASH_VALUE((byte) 0x72),
    UNKNOWN_PSK_IDENTITY((byte) 0x73);

    private byte desc;
    final private static Map<Byte, EAlertDescription> ID_MAP;

    static {
        ID_MAP = new HashMap<>(values().length);
        for (EAlertDescription alert : EAlertDescription.values()) {
            ID_MAP.put(alert.getAlertDescriptionId(), alert);
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
