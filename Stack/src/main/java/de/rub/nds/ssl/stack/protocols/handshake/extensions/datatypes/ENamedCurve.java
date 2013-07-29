package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import java.util.HashMap;
import java.util.Map;

/**
 * Named Curves as defined in RFC4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jul 27, 2013
 */
public enum ENamedCurve {

    /**
     * TODO JavaDoc.
     */
    SECT_163_K1(new byte[]{0x00, 0x01}),
    SECT_163_R1(new byte[]{0x00, 0x02}),
    SECT_163_R2(new byte[]{0x00, 0x03}),
    SECT_193_R1(new byte[]{0x00, 0x04}),
    SECT_193_R2(new byte[]{0x00, 0x05}),
    SECT_233_K1(new byte[]{0x00, 0x06}),
    SECT_233_R1(new byte[]{0x00, 0x07}),
    SECT_239_K1(new byte[]{0x00, 0x08}),
    SECT_283_K1(new byte[]{0x00, 0x09}),
    SECT_283_R1(new byte[]{0x00, 0x0A}),
    SECT_409_K1(new byte[]{0x00, 0x0B}),
    SECT_409_R1(new byte[]{0x00, 0x0C}),
    SECT_571_K1(new byte[]{0x00, 0x0D}),
    SECT_571_R1(new byte[]{0x00, 0x0E}),
    SECP_160_K1(new byte[]{0x00, 0x0F}),
    SECP_160_R1(new byte[]{0x00, 0x10}),
    SECP_160_R2(new byte[]{0x00, 0x11}),
    SECP_192_K1(new byte[]{0x00, 0x12}),
    SECP_192_R1(new byte[]{0x00, 0x13}),
    SECP_224_K1(new byte[]{0x00, 0x14}),
    SECP_224_R1(new byte[]{0x00, 0x15}),
    SECP_256_K1(new byte[]{0x00, 0x16}),
    SECP_256_R1(new byte[]{0x00, 0x17}),
    SECP_384_R1(new byte[]{0x00, 0x18}),
    SECP_521_R1(new byte[]{0x00, 0x19}),
    ARBITRARY_EXPLICIT_PRIME_CURVES(new byte[]{(byte)0xFF, 0x01}),
    ARBITRARY_EXPLICIT_CHAR2_CURVES(new byte[]{(byte)0xFF, 0x02});
    /**
     * Length of the name id: 2 Bytes.
     */
    public static final int LENGTH_ENCODED = 2;
    /**
     * Map of an id to the curve.
     */
    private static final Map<Integer, ENamedCurve> ID_MAP =
            new HashMap<Integer, ENamedCurve>(26);
    /**
     * Id of the named curve.
     */
    private final byte[] id;
    /**
     * Bits in byte.
     */
    private static final int BITS_IN_BYTE = 8;

    static {
        byte[] id;
        for (ENamedCurve tmp : ENamedCurve.values()) {
            id = tmp.getId();
            ID_MAP.put(id[0] << BITS_IN_BYTE | id[1] & 0xff, tmp);
        }
    }

    /**
     * Construct a curve with the given id.
     *
     * @param idBytes Id of this curve
     */
    private ENamedCurve(final byte[] idBytes) {
        id = idBytes;
    }

    /**
     * Get the Id of this named curve.
     *
     * @return Id as byte array
     */
    public byte[] getId() {
        byte[] tmp = new byte[id.length];
        // deep copy
        System.arraycopy(id, 0, tmp, 0, tmp.length);

        return tmp;
    }
    
    /**
     * Get a human readable representation of this named curve.
     */
    @Override
    public String toString() {
    	byte[] tmpID = this.getId();
    	return "ENamedCurve: Major " + tmpID[0] + " Minor " + tmpID[1];
    }

    /**
     * Get the named curve for a given id.
     *
     * @param id ID of the desired named curve
     * @return Associated named curve
     */
    public static ENamedCurve getNamedCurve(final byte[] id) {
        final int namedCurve;
        if (id == null || id.length != LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "ID must not be null and have a length of exactly "
                    + LENGTH_ENCODED + " bytes.");
        }

        namedCurve = id[0] << BITS_IN_BYTE | id[1] & 0xff;

        if (!ID_MAP.containsKey(namedCurve)) {
            throw new IllegalArgumentException("No such named curve.");
        }

        return ID_MAP.get(namedCurve);
    }
}
