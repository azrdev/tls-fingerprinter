package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import java.util.HashMap;
import java.util.Map;

/**
 * EC Point Formats as defined in RFC4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jul 29, 2013
 */
public enum EECPointFormat {

    /**
     * Uncompressed point format - mandatory.
     */
    UNCOMPRESSED((byte) 0x00),
    /**
     * Compressed representation of points (Only single bit of Y-Coordinate).
     */
    ANSI_X962_COMPRESSED_PRIME((byte) 0x01),
    /**
     * Compressed representation of points (Only single bit of Y-Coordinate) -
     * Characteristic 2 curves only.
     */
    ANSI_X962_COMPRESSED_CHAR2((byte) 0x02);
    /**
     * Length of id: 1 Byte.
     */
    public static final int LENGTH_ENCODED = 1;
    /**
     * Map of an id to the Format.
     */
    private static final Map<Byte, EECPointFormat> ID_MAP =
            new HashMap<Byte, EECPointFormat>(3);
    /**
     * Id of the named curve.
     */
    private final byte id;

    static {
        for (EECPointFormat tmp : EECPointFormat.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a point format with the given id.
     *
     * @param id Id of this point format
     */
    private EECPointFormat(final byte id) {
        this.id = id;
    }

    /**
     * Get the Id of this point format.
     *
     * @return Id
     */
    public byte getId() {
        return id;
    }

    /**
     * Get the EC Point Format for a given id.
     *
     * @param id ID of the desired EC Point Format
     * @return Associated EC Point Format
     */
    public static EECPointFormat getECPointFormat(final byte id) {
        if (!ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException("No such point format.");
        }

        return ID_MAP.get(id);
    }
}
