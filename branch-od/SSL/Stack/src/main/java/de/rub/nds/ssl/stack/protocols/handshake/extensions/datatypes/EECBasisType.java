package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import java.util.HashMap;
import java.util.Map;

/**
 * EC Basis Types for characteristic-2 fields as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2013
 */
public enum EECBasisType {

    /**
     * Trionomial basis representation.
     */
    EC_BASIS_TRINOMIAL((byte) 0x01),
    /**
     * Pentanomial basis representation.
     */
    EC_BASIS_PENTANOMIAL((byte) 0xFF);
    /**
     * Length of id: 1 Byte.
     */
    public static final int LENGTH_ENCODED = 1;
    /**
     * Map of an id to the Basis Type.
     */
    private static final Map<Byte, EECBasisType> ID_MAP =
            new HashMap<Byte, EECBasisType>(2);
    /**
     * Id of the basis type.
     */
    private final byte id;

    static {
        for (EECBasisType tmp : EECBasisType.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a basis type with the given id.
     *
     * @param id Id of this curve type
     */
    private EECBasisType(final byte id) {
        this.id = id;
    }

    /**
     * Get the Id of this basis type.
     *
     * @return Id
     */
    public byte getId() {
        return id;
    }

    /**
     * Get the EC Basis Type for a given id.
     *
     * @param id ID of the desired EC Basis Type
     * @return Associated EC Basis Type
     */
    public static EECBasisType getECBasisType(final byte id) {
        if (!ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException("No such basis type.");
        }

        return ID_MAP.get(id);
    }
}
