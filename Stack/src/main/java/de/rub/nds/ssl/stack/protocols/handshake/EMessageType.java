package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.exceptions.UnknownHandshakeMessageTypeException;

import java.util.HashMap;
import java.util.Map;

/**
 * Message types for SSL/TLS handshake
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 14, 2011
 */
public enum EMessageType {

    HELLO_REQUEST((byte) 0x0, HelloRequest.class),
    CLIENT_HELLO((byte) 0x1, ClientHello.class),
    SERVER_HELLO((byte) 0x2, ServerHello.class),
    HELLO_VERIFY_REQUEST((byte) 0x3, null),
    NEW_SESSION_TICKET((byte) 0x4, null),
    CERTIFICATE((byte) 0xb, Certificate.class),
    SERVER_KEY_EXCHANGE((byte) 0xc, ServerKeyExchange.class),
    CERTIFICATE_REQUEST((byte) 0xd, null),
    SERVER_HELLO_DONE((byte) 0xe, ServerHelloDone.class),
    CERTIFICATE_VERIFY((byte) 0xf, null),
    CLIENT_KEY_EXCHANGE((byte) 0x10, ClientKeyExchange.class),
    FINISHED((byte) 0x14, Finished.class),
    CERTIFICATE_URL((byte) 0x15, null),
    CERTIFICATE_STATUS((byte) 0x16, CertificateStatus.class),
    SUPPLEMENTAL_DATA((byte) 0x17, null);

    /**
     * Length of the message type id: 1 Byte
     */
    final public static int LENGTH_ENCODED = 1;

    final private static Map<Byte, EMessageType> ID_MAP;
    final private byte id;
    final private Class implementingClass;

    static {
        ID_MAP = new HashMap<>(values().length);
        for (EMessageType tmp : EMessageType.values()) {
            ID_MAP.put(tmp.getId(), tmp);
        }
    }

    /**
     * Construct a message type with the given id
     *
     * @param id Id of this message type
     */
    EMessageType(final byte id, final Class implementer) {
        this.id = id;
        this.implementingClass = implementer;
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
            throw new UnknownHandshakeMessageTypeException(id);
        }

        return ID_MAP.get(id);
    }
}
