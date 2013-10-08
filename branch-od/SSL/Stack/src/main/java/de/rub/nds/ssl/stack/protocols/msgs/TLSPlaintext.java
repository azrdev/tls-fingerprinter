package de.rub.nds.ssl.stack.protocols.msgs;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * TLSPlaintext message as defined in Chapter 6.2.1 of RFC 2246.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 07, 2012
 */
public class TLSPlaintext extends ARecordFrame {

    /**
     * Data record fragment.
     */
    private byte[] fragment = null;

    /**
     * Initializes a plain data record.
     *
     * @param message SSL data record
     * @param chained Decode single or chained with underlying frames
     */
    public TLSPlaintext(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a plain data record.
     *
     * @param protocolVersion Protocol version of this message
     */
    public TLSPlaintext(final EProtocolVersion protocolVersion) {
        super(EContentType.APPLICATION, protocolVersion);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] encode(final boolean chained) {
        super.setPayload(this.fragment);
        return chained ? super.encode(true) : this.fragment.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        byte[] tmpBytes;
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // 1. extract data fragment
        tmpBytes = new byte[payloadCopy.length];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        setFragment(tmpBytes);
    }
    
    /**
     * change content type for application phase messages
     * 
     * @param contentType 
     */
    
    public void setCType(EContentType contentType){
        super.setContentType(contentType);
    }

    /**
     * Set the data fragment of this record.
     *
     * @param fragm Data fragment
     */
    public final void setFragment(final byte[] fragm) {
        this.fragment = fragm.clone();
    }

    /**
     * Get the data fragment of this record.
     *
     * @return Data fragment
     */
    public final byte[] getFragment() {
        return this.fragment.clone();
    }
}
