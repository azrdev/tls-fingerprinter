package de.rub.nds.ssl.stack.protocols.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * Compression methods for TLS, as defined in RFC 5246
 *
 * @author jBiegert azrdev@qrdn.de
 */
public enum ECompressionMethod {
    /**
     * null compression specified in RFC 5246 and always supported
     */
    NULL((byte) 0x00),
    /**
     * DEFLATE compression specified in RFC 3749
     */
    DEFLATE((byte) 0x01);

    final public static int LENGTH_ENCODED = 1;
    final private byte id;

    private static Map<Byte, ECompressionMethod> ID_MAP = new HashMap<>(values().length);

    static {
        for(ECompressionMethod method : values()) {
            ID_MAP.put(method.getId(), method);
        }
    }

    private ECompressionMethod(byte id) {
        this.id = id;
    }

    public byte getId() {
        return id;
    }

    /**
     * @return the ECompressionMethod encoded by given id
     * @throws java.lang.IllegalArgumentException if id denotes no compression method
     */
    public static ECompressionMethod getCompressionMethod(byte id) {
        if(! ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException(String.format(
                    "Unknown compression method: %02x", id));
        }

        return ID_MAP.get(id);
    }
}
