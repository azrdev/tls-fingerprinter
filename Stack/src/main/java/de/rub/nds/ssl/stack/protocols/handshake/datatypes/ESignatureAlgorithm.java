package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.exceptions.UnknownSignatureAlgorithmException;

import java.util.HashMap;
import java.util.Map;

/**
 * Algorithm used for signing.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 */
public enum ESignatureAlgorithm {

    /**
     * Anonymous.
     */
    anon((byte) 0x00),
    /**
     * RSA signature.
     */
    RSA((byte) 0x01),
    /**
     * DSS signature.
     */
    DSS((byte) 0x02),
    /**
     * ECDSA
     */
    ECDSA((byte) 0x03);

    public static final int LENGTH_ENCODED = 1;

    private final byte id;

    private static final Map<Byte, ESignatureAlgorithm> ID_MAP;

    static {
        ID_MAP = new HashMap<>(values().length);
        for(ESignatureAlgorithm sa : values()) {
            ID_MAP.put(sa.id, sa);
        }
    }

    ESignatureAlgorithm(byte id) {
        this.id = id;
    }

    public static ESignatureAlgorithm getSignatureAlgorithm(final byte id) {
        if(! ID_MAP.containsKey(id)) {
            throw new UnknownSignatureAlgorithmException(id);
        }

        return ID_MAP.get(id);
    }

    public byte getId() {
        return id;
    }
}
