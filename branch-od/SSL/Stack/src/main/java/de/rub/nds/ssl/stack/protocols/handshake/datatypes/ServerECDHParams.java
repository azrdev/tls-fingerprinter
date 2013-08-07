package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECParameters;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;

/**
 * ServerECDHParams part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.1 Jul 30, 2013
 */
public class ServerECDHParams extends APubliclySerializable implements
        IExchangeKeys {

    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED =
            ECParameters.LENGTH_MINIMUM_ENCODED
            + ECPoint.LENGTH_MINIMUM_ENCODED;
    /**
     * Elliptic curve domain parameters.
     */
    private ECParameters curveParameters;
    /**
     * Ephemeral ECDH Point (public key).
     */
    private ECPoint publicKey;

    /**
     * Initializes a ServerDHParams part as defined in RFC 2246.
     *
     * @param message ServerDHParams part in encoded form
     */
    public ServerECDHParams(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public final byte[] encode(final boolean chained) {
        int pointer = 0;

        byte[] curveParams = getCurveParameters().encode(false);
        byte[] publicPoint = getPublicKey().encode(false);
        byte[] serverDHParams;
        serverDHParams = new byte[curveParams.length + publicPoint.length];

        /*
         * add the curve parameters
         */
        System.arraycopy(curveParams, 0, serverDHParams, pointer,
                curveParams.length);
        pointer += curveParams.length;

        /*
         * add the public point (public key)
         */
        System.arraycopy(publicPoint, 0, serverDHParams, pointer,
                publicPoint.length);
        pointer += publicPoint.length;

        return serverDHParams;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        byte[] tmpBytes;
        // deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);

        int pointer = 0;
        // 1. extract curve parameters
        ECParameters params = new ECParameters(paramCopy);
        setCurveParameters(params);
        tmpBytes = getCurveParameters().encode(false);
        pointer += tmpBytes.length;
        // 2. extract public key
        tmpBytes = new byte[paramCopy.length - tmpBytes.length];
        System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setPublicKey(new ECPoint(tmpBytes));
        pointer += tmpBytes.length;
    }

    /**
     * Get the curve parameters of this message part.
     *
     * @return The curve parameters of this message part
     */
    public ECParameters getCurveParameters() {
        return new ECParameters(curveParameters.encode(false));
    }

    /**
     * Set the curve parameters of this message part.
     *
     * @param point The curve parameters to be used for this message part
     */
    public void setCurveParameters(final ECParameters curveParameters) {
        this.curveParameters = new ECParameters(curveParameters.encode(false));
    }

    /**
     * Get the public key (point) of this message part.
     *
     * @return The public key point of this message part
     */
    public ECPoint getPublicKey() {
        return new ECPoint(publicKey.encode(false));
    }

    /**
     * Set the public key of this message part.
     *
     * @param publicKey The public key to be used for this message part
     */
    public void setPublicKey(final ECPoint publicKey) {
        this.publicKey = new ECPoint(publicKey.encode(false));
    }
}
