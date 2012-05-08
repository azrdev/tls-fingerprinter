package de.rub.nds.research.ssl.stack.protocols.msgs;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * TLSPlaintext message as defined in Chapter 6.2.1 of RFC 2246
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 07, 2012
 */
public class TLSPlaintext extends ARecordFrame {

    private byte[] fragment = null;

    /**
     * Initializes a plain data record
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
     * Initializes a plain data record
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
        return chained ? super.encode(true) : fragment;
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
     * Set the data fragment of this record
     *
     * @param fragment Data fragment
     */
    public void setFragment(byte[] fragment) {
        this.fragment = fragment;
    }

    /**
     * Get the data fragment of this record
     *
     * @return Data fragment
     */
    public byte[] getFragment() {
        return this.fragment;
    }
}
