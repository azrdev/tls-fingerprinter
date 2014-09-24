package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EHashAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;

import java.util.Arrays;

/**
 * Signature and Hash Algorithm tuple as in RFC 5246
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SignatureAndHashAlgorithm extends APubliclySerializable {
    public static final int LENGTH_ENCODED =
            EHashAlgorithm.LENGTH_ENCODED + ESignatureAlgorithm.LENGTH_ENCODED;

    private EHashAlgorithm hashAlgorithm;
    private ESignatureAlgorithm signatureAlgorithm;

    public SignatureAndHashAlgorithm( EHashAlgorithm ha, ESignatureAlgorithm sa) {
        setHashAlgorithm(ha);
        setSignatureAlgorithm(sa);
    }

    public SignatureAndHashAlgorithm(final byte[] encoded) {
        decode(encoded, true);
    }

    public EHashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(EHashAlgorithm hashAlgorithm) {
        if(hashAlgorithm == null)
            throw new IllegalArgumentException("hashAlgorithm must not be null");

        this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(final byte id) {
        setHashAlgorithm(EHashAlgorithm.getHashAlgorithm(id));
    }

    public ESignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(ESignatureAlgorithm signatureAlgorithm) {
        if(signatureAlgorithm == null)
            throw new IllegalArgumentException("signatureAlgorithm must not be null");

        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setSignatureAlgorithm(final byte id) {
        setSignatureAlgorithm(ESignatureAlgorithm.getSignatureAlgorithm(id));
    }

    /**
     * {@inheritDoc}
     * @param chained <b>ignored</b>
     */
    @Override
    public byte[] encode(boolean chained) {
        byte[] encoded = new byte[LENGTH_ENCODED];

        encoded[0] = hashAlgorithm.getId();
        encoded[1] = signatureAlgorithm.getId();

        return encoded;
    }

    /**
     * {@inheritDoc}
     * @param chained <b>ignored</b>
     */
    @Override
    public void decode(byte[] message, boolean chained) {
        if(message.length != LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "Invalid length of SignatureAndHashAlgorithm");
        }

        int pointer = 0;
        byte tmp;

        tmp = message[pointer];
        setHashAlgorithm(tmp);
        pointer += EHashAlgorithm.LENGTH_ENCODED;

        tmp = message[pointer];
        setSignatureAlgorithm(tmp);
        pointer += ESignatureAlgorithm.LENGTH_ENCODED;
    }
}
