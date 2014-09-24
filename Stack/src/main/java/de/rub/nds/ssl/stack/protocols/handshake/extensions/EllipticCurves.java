package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;

/**
 * Elliptic curve extension as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 27, 2013
 */
public final class EllipticCurves extends AExtension {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * Array of supported elliptic curves in preferred order.
     */
    private ENamedCurve[] supportedCurves;

    /**
     * Initializes an Elliptic Curves Extension as defined in RFC 4492. All
     * supported named curves are added by default at construction time.
     */
    public EllipticCurves() {
        setExtensionType(EExtensionType.ELLIPTIC_CURVES);
        setSupportedCurves(ENamedCurve.values());
    }

    /**
     * Initializes an Elliptic Curves Extension as defined in RFC 4492.
     *
     * @param message Elliptic Curves Extension in encoded form
     */
    public EllipticCurves(final byte[] message) {
        this.decode(message, true);
    }

    /**
     * Get the supported elliptic curves.
     *
     * @return Supported curves.
     */
    public ENamedCurve[] getSupportedCurves() {
        // deep copy
        ENamedCurve[] tmp = new ENamedCurve[supportedCurves.length];
        System.arraycopy(supportedCurves, 0, tmp, 0, supportedCurves.length);

        return tmp;
    }

    /**
     * Set the supported curves.
     *
     * @param curves Curves to set
     */
    public void setSupportedCurves(final ENamedCurve[] curves) {
        if (curves == null) {
            throw new IllegalArgumentException("Curves must not be null!");
        }
        // keep the array clean and small, Mr. Proper will be proud!
        this.supportedCurves = new ENamedCurve[curves.length];
        // refill, deep copy
        System.arraycopy(curves, 0, this.supportedCurves, 0, curves.length);
    }

    /**
     * {@inheritDoc} 
     * EllipticCurves representation 2 + x*2 bytes for x curves.
     * 
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        Integer curvesBytes = supportedCurves.length * ENamedCurve.LENGTH_ENCODED;
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + curvesBytes];
        byte[] tmpID;

        // length
        tmpID = buildLength(curvesBytes, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmpID, 0, tmp, pointer, tmpID.length);
        //pointer += tmpID.length;

        for (int i = 1; i - 1 < supportedCurves.length; i++) {
            tmpID = supportedCurves[i - 1].getId();
            tmp[i * ECipherSuite.LENGTH_ENCODED] = tmpID[0];
            tmp[i * ECipherSuite.LENGTH_ENCODED + 1] = tmpID[1];
        }

        setExtensionData(tmp);
        return super.encode(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        final int curvesCount;
        final byte[] tmpCurves = getExtensionData();
        
        // check size
        if (tmpCurves.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "Elliptic curves extension too short.");
        }
        curvesCount = (extractLength(tmpCurves, 0,
                LENGTH_LENGTH_FIELD) >> 1) & 0xff;

        if (tmpCurves.length - LENGTH_LENGTH_FIELD != curvesCount
                * ENamedCurve.LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "Elliptic Curves extension length invalid.");
        }

        // extract curves
        ENamedCurve[] extractedCurves = new ENamedCurve[curvesCount];
        for (int j = 0, i = LENGTH_LENGTH_FIELD; j < curvesCount;
                i += ENamedCurve.LENGTH_ENCODED, j++) {
            extractedCurves[j] = ENamedCurve.getNamedCurve(
                    new byte[]{tmpCurves[i], tmpCurves[i + 1]});
        }
        setSupportedCurves(extractedCurves);
    }
}
