package de.rub.nds.ssl.stack.protocols.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * Content types of SSL/TLS.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 14, 2011
 */
public enum EContentType {

    /**
     * Change cipher spec message.
     */
    CHANGE_CIPHER_SPEC((byte) 0x14),
    /**
     * Alert message.
     */
    ALERT((byte) 0x15),
    /**
     * Handshake message.
     */
    HANDSHAKE((byte) 0x16),
    /**
     * Application message.
     */
    APPLICATION((byte) 0x17);
    /**
     * Length of the content type id: 1 Byte.
     */
    public static final int LENGTH_ENCODED = 1;
    /**
     * Map byte value to content type.
     */
    private static final Map<Byte, EContentType> ID_MAP =
            new HashMap<Byte, EContentType>(4);
    /**
     * Content type id.
     */
    private final byte id;

    static {
        byte[] id;
        for (EContentType tmp : EContentType.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a version with the given id.
     *
     * @param idBytes Id of this version
     */
    EContentType(final byte idBytes) {
        id = idBytes;
    }

    /**
     * Get the Id of this content type.
     *
     * @return Id as byte
     */
    public byte getId() {
        return this.id;
    }

    /**
     * Get the content type for a given id.
     *
     * @param id ID of the desired content type
     * @return Associated content type
     */
    public static EContentType getContentType(final byte id) {
        if (!ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException(
                    "No content type with this ID registered.");
        }

        return ID_MAP.get(id);
    }
}
