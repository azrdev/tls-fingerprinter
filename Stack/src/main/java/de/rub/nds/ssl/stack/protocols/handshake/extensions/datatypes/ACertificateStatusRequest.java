package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ECertificateStatusType;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public abstract class ACertificateStatusRequest extends APubliclySerializable {

    private ECertificateStatusType type;

    public ECertificateStatusType getType() {
        return type;
    }

    protected void setType(ECertificateStatusType type) {
        if(type == null)
            throw new IllegalArgumentException("CertificateStatus Type must not be null");

        this.type = type;
    }

    protected void setType(final byte id) {
        setType(ECertificateStatusType.getCertificateStatusType(id));
    }
}
