package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import java.util.HashMap;
import java.util.Map;

/**
 * TLS supported extensions. (data based on
 * http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml)
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Feb 04, 2013
 */
public enum EExtensionType{

    /**
     * Server Name (RFC6066).
     */
    SERVER_NAME(new byte[]{0x00, 0x0}, null),
    /**
     * Max fragment length (RFC6066).
     */
    MAX_FRAGMENT_LENGTH(new byte[]{0x00, 0x01}, null),
    /**
     * Client Certificate URL (RFC6066).
     */
    CLIENT_CERTIFICATE_URL(new byte[]{0x00, 0x02}, null),
    /**
     * Truncated CA keys (RFC6066).
     */
    TRUNCATED_CA_KEYS(new byte[]{0x00, 0x03}, null),
    /**
     * Truncated HMAC (RFC6066).
     */
    TRUNCATED_HMAC(new byte[]{0x00, 0x04}, null),
    /**
     * Status Request (RFC6066).
     */
    STATUS_REQUEST(new byte[]{0x00, 0x05}, null),
    /**
     * User mapping (RFC4681).
     */
    USER_MAPPING(new byte[]{0x00, 0x06}, null),
    /**
     * Client authz (RFC5878).
     */
    CLIENT_AUTHZ(new byte[]{0x00, 0x07}, null),
    /**
     * Server authz (RFC5878).
     */
    SERVER_AUTHZ(new byte[]{0x00, 0x08}, null),
    /**
     * Cert type (RFC6091).
     */
    CERT_TYPE(new byte[]{0x00, 0x09}, null),
    /**
     * Elliptic curves (RFC4492).
     */
    ELLIPTIC_CURVES(new byte[]{0x00, 0x0A}, EllipticCurves.class),
    /**
     * EC point formats (RFC4492).
     */
    EC_POINT_FORMATS(new byte[]{0x00, 0x0B}, SupportedPointFormats.class),
    /**
     * SRP (RFC5054).
     */
    SRP(new byte[]{0x00, 0x0C}, null),
    /**
     * Signature algorithms (RFC5246).
     */
    SIGNATURE_ALGORITHMS(new byte[]{0x00, 0x0D}, null),
    /**
     * Use SRTP (RFC5764).
     */
    USE_SRTP(new byte[]{0x00, 0x0E}, null),
    /**
     * Heartbeat (RFC6520).
     */
    HEARTBEAT(new byte[]{0x00, 0x0F}, null),
    /**
     * Session ticket TLS (RFC4507).
     */
    SESSION_TICKET_TLS(new byte[]{0x00, 0x23}, null),
    /**
     * Renegotiation info (RFC5746).
     */
    RENEGOTIATION_INFO(new byte[]{(byte) ((byte) 255 & 0xFF), 0x01}, null);
   
    /**
     * Length of the extension id: 2 Bytes.
     */
    public static final int LENGTH_ENCODED = 2;
    /**
     * Map of an id to the extension.
     */
    private static final Map<Integer, EExtensionType> ID_MAP = 
            new HashMap<>(16);
    /**
     * Id of the extension.
     */
    private final byte[] id;
    /**
     * Implementing class of this extension.
     */
    private final Class implementingClass;


    static {
        byte[] id;
        for (EExtensionType tmp : EExtensionType.values()) {
            id = tmp.getId();
            ID_MAP.put((id[0]&0xff) << Utility.BITS_IN_BYTE | id[1] & 0xff, tmp);
        }
    }

    /**
     * Construct a version with the given id.
     *
     * @param idBytes Id of this version
     * @param implementer Implementing class
     */
    private EExtensionType(final byte[] idBytes, final Class implementer) {
        id = idBytes;
        this.implementingClass = implementer;
    }

    /**
     * Get the Id of this extension.
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
    @Override
    public String toString() {
        byte[] id = this.getId();
        return "EExtension: Major " + id[0] + " Minor " + id[1];
    }

    /**
     * Get the extension for a given id.
     *
     * @param id ID of the desired extension
     * @return Associated extension
     */
    public static EExtensionType getExtension(final byte[] id) {
        final int extension;
        if (id == null || id.length != LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "ID must not be null and have a length of exactly "
                    + LENGTH_ENCODED + " bytes.");
        }

        extension = (id[0]&0xff) << Utility.BITS_IN_BYTE | id[1] & 0xff;

        if (!ID_MAP.containsKey(extension)) {
            throw new IllegalArgumentException("No such extension: " + extension);
        }

        return ID_MAP.get(extension);
    }
    
    /**
     * Get implementing class for this extension type.
     * @return Implementing class
     */
    public Class getImplementingClass() {
        return this.implementingClass;
    }
}
