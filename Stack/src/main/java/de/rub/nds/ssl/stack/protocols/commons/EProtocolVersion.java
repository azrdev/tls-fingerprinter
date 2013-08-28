package de.rub.nds.ssl.stack.protocols.commons;

import de.rub.nds.ssl.stack.Utility;
import java.util.HashMap;
import java.util.Map;

/**
 * Supported protocol versions of SSL/TLS.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 14, 2011
 */
public enum EProtocolVersion {

    /**
     * SSL 3.0 protocol version.
     */
    SSL_3_0(new byte[]{0x3, 0x0}),
    /**
     * TLS 1.0 protocol version.
     */
    TLS_1_0(new byte[]{0x3, 0x1}),
    /**
     * TLS 1.1 protocol version.
     */
    TLS_1_1(new byte[]{0x3, 0x2}),
    /**
     * TLS 1.2 protocol version.
     */
    TLS_1_2(new byte[]{0x3, 0x3}),
    /**
     * TLS 1.3 protocol version. For testing purposes!
     */
    TLS_1_3(new byte[]{0x3, 0x4});
    /**
     * Length of the protocol version id: 2 Bytes.
     */
    public static final int LENGTH_ENCODED = 2;
    /**
     * Map of an id to the protocol version.
     */
    private static final Map<Integer, EProtocolVersion> ID_MAP =
            new HashMap<Integer, EProtocolVersion>(4);
    /**
     * Id of the protocol version.
     */
    private final byte[] id;

    static {
        byte[] id;
        for (EProtocolVersion tmp : EProtocolVersion.values()) {
            id = tmp.getId();
            ID_MAP.put(id[0] << Utility.BITS_IN_BYTE | id[1] & 0xff, tmp);
        }
    }

    /**
     * Construct a version with the given id.
     *
     * @param idBytes Id of this version
     */
    private EProtocolVersion(final byte[] idBytes) {
        id = idBytes;
    }

    /**
     * Get the Id of this protocol version.
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
     * Get a human readable representation.
     */
    public String toString() {
    	byte[] id = this.getId();
    	return "EProtocolVersion: Major " + id[0] + " Minor " + id[1];
    }

    /**
     * Get the protocol version for a given id.
     *
     * @param id ID of the desired protocol version
     * @return Associated protocol version
     */
    public static EProtocolVersion getProtocolVersion(final byte[] id) {
        final int protocolVersion;
        if (id == null || id.length != LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "ID must not be null and have a length of exactly "
                    + LENGTH_ENCODED + " bytes.");
        }

        protocolVersion = id[0] << Utility.BITS_IN_BYTE | id[1] & 0xff;

        if (!ID_MAP.containsKey(protocolVersion)) {
            throw new IllegalArgumentException("No such protocol version: " 
                    + Utility.bytesToHex(id));
        }

        return ID_MAP.get(protocolVersion);
    }
}
