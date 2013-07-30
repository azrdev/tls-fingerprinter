package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.*;
import java.util.HashMap;
import java.util.Map;

/**
 * EC Curve Type as defined in RFC4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jul 30, 2013
 */
public enum EECCurveType {

    /**
     * Elliptic curve domain parameters are conveyed verbosely and the 
     * underlying finite field is a prime field.
     */
    EXPLICIT_PRIME((byte) 0x01),
    /**
     * Elliptic curve domain parameters are conveyed verbosely and the 
     * underlying finite field is a characteristic-2 field.
     */
    EXPLICIT_CHAR2((byte) 0x02),
    /**
     * Elliptic curve is a named curve. This is definitively your favorite
     * choice!
     */
    NAMED_CURVE((byte) 0x02);
    /**
     * Length of id: 1 Byte.
     */
    public static final int LENGTH_ENCODED = 1;
    /**
     * Map of an id to the Curve Type.
     */
    private static final Map<Byte, EECCurveType> ID_MAP =
            new HashMap<Byte, EECCurveType>(3);
    /**
     * Id of the curve type.
     */
    private final byte id;

    static {
        for (EECCurveType tmp : EECCurveType.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a curve type with the given id.
     *
     * @param id Id of this curve type
     */
    private EECCurveType(final byte id) {
        this.id = id;
    }

    /**
     * Get the Id of this curve type.
     *
     * @return Id
     */
    public byte getId() {
        return id;
    }

    /**
     * Get the EC Curve Type for a given id.
     *
     * @param id ID of the desired EC Curve Type
     * @return Associated EC Curve Type
     */
    public static EECCurveType getECCurveType(final byte id) {
        if (!ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException("No such curve type.");
        }

        return ID_MAP.get(id);
    }
}
