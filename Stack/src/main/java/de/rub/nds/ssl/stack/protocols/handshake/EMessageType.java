package de.rub.nds.ssl.stack.protocols.handshake;

import java.util.HashMap;
import java.util.Map;

/**
 * Message types for SSL/TLS
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 14, 2011
 */
public enum EMessageType {

    HELLO_REQUEST((byte) 0x0, HelloRequest.class),
    CLIENT_HELLO((byte) 0x1, ClientHello.class),
    SERVER_HELLO((byte) 0x2, ServerHello.class),
    CERTIFICATE((byte) 0xb, Certificate.class),
    SERVER_KEY_EXCHANGE((byte) 0xc, ServerKeyExchange.class),
    CERTIFICATE_REQUEST((byte) 0xd, null),
    SERVER_HELLO_DONE((byte) 0xe, ServerHelloDone.class),
    CERTIFICATE_VERIFY((byte) 0xf, null),
    CLIENT_KEY_EXCHANGE((byte) 0x10, null),
    FINISHED((byte) 0x14, null);
    /**
     * Length of the message type id: 1 Byte
     */
    final public static int LENGTH_ENCODED = 1;
    final private static Map<Byte, EMessageType> ID_MAP =
            new HashMap<Byte, EMessageType>(10);
    final private byte id;
    final private Class implementingClass;

    static {
        byte[] id;
        for (EMessageType tmp : EMessageType.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a message type with the given id
     *
     * @param id Id of this message type
     */
    EMessageType(final byte id, final Class implementor) {
        this.id = id;
        this.implementingClass = implementor;
    }

    /**
     * Get the Id of this message type
     *
     * @return Id as byte
     */
    public byte getId() {
        return this.id;
    }

    /**
     * Get implementing class to id
     */
    public Class getImplementingClass() {
        return this.implementingClass;
    }

    /**
     * Get the message type for a given id
     *
     * @param id ID of the desired message type
     * @return Associated message type
     */
    public static EMessageType getMessageType(final byte id) {
        if (!ID_MAP.containsKey(id)) {
            throw new IllegalArgumentException(
                    "No message type with this ID registered.");
        }

        return ID_MAP.get(id);
    }
}
