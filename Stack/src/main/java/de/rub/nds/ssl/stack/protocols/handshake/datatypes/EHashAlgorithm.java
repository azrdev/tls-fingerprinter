package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.exceptions.UnknownHashAlgorithmException;

import java.util.HashMap;
import java.util.Map;

/**
 * Hash functions.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 */
public enum EHashAlgorithm {

    /**
     * RFC 5246 "Provided for future extensibility"
     */
    //NONE((byte) 0x00),

    /**
     * MD5 hash.
     */
    MD5((byte) 0x01),

    /**
     * SHA1 hash.
     */
    SHA1((byte) 0x02),

    SHA224((byte) 0x03),
    SHA256((byte) 0x04),
    SHA384((byte) 0x05),
    SHA512((byte) 0x06),
    ;

    public static final int LENGTH_ENCODED = 1;

    private final byte id;

    private static final Map<Byte, EHashAlgorithm> ID_MAP;

    static {
        ID_MAP = new HashMap<>(values().length);
        for(EHashAlgorithm ha : values()) {
            ID_MAP.put(ha.id, ha);
        }
    }

    EHashAlgorithm(byte id) {
        this.id = id;
    }

    public static EHashAlgorithm getHashAlgorithm(final byte id) {
        if(! ID_MAP.containsKey(id)) {
            throw new UnknownHashAlgorithmException(id);
        }

        return ID_MAP.get(id);
    }

    public byte getId() {
        return id;
    }
}
