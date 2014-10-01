package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ACertificateStatusRequest;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.OCSPStatusRequest;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.exceptions.UnknownCertificateStatusTypeException;

import java.util.HashMap;
import java.util.Map;

/**
 * Type of Certificate Status Request as in RFC 6066 section 8
 *
 * @author jBiegert azrdev@qrdn.de
 */
public enum ECertificateStatusType {
    /**
     * RFC 6066
     */
    OCSP((byte) 0x01),
    /**
     * RFC 6961
     */
    OCSP_MULTI((byte) 0x02);

    public static final int LENGTH_ENCODED = 1;

    private static final Map<Byte, ECertificateStatusType> ID_MAP;

    static {
        ID_MAP = new HashMap<>(values().length);
        for(ECertificateStatusType cst : values()) {
            ID_MAP.put(cst.getId(), cst);
        }
    }

    private final byte id;

    public byte getId() {
        return id;
    }

    ECertificateStatusType(byte id) {
        this.id = id;
    }

    public static ECertificateStatusType getCertificateStatusType(final byte id) throws
            UnknownCertificateStatusTypeException {
        if(! ID_MAP.containsKey(id))
            throw new UnknownCertificateStatusTypeException(id);

        return ID_MAP.get(id);
    }

    public ACertificateStatusRequest getRequest(byte[] message) {
        switch(this) {
            case OCSP:
                return new OCSPStatusRequest(message);
            default:
                throw new IllegalArgumentException("No Request class implementing " +
                        this);
        }
    }

    public ACertificateStatusResponse getResponse(final byte[] message) {
        switch (this) {
            case OCSP:
                return new OCSPStatusResponse(message);
            default:
                throw new IllegalArgumentException("No Response class implementing " +
                        this);
        }
    }
}
