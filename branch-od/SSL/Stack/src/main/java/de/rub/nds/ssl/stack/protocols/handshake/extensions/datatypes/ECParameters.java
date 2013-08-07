package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECBasisType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECCurveType;

/**
 * ECParameters part - as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 31, 2013
 */
public final class ECParameters extends APubliclySerializable {

    /**
     * Length filed of prime p.
     */
    private static final int LENGTH_FIELD_PRIME_P = 1;
    /**
     * Length filed of m.
     */
    private static final int LENGTH_M = 2;
    /**
     * Length filed of order.
     */
    private static final int LENGTH_FIELD_ORDER = 1;
    /**
     * Length filed of cofactor.
     */
    private static final int LENGTH_FIELD_COFACTOR = 1;
    /**
     * Length filed of k.
     */
    private static final int LENGTH_FIELD_K = 1;
    /**
     * Length filed of k1.
     */
    private static final int LENGTH_FIELD_K1 = 1;
    /**
     * Length filed of k2.
     */
    private static final int LENGTH_FIELD_K2 = 1;
    /**
     * Length filed of k3.
     */
    private static final int LENGTH_FIELD_K3 = 1;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED =
            EECCurveType.LENGTH_ENCODED + ENamedCurve.LENGTH_ENCODED;
    /**
     * Type of the contained curve domain parameters.
     */
    private EECCurveType curveType;
    /**
     * Prime p of field Fp.
     */
    private byte[] primeP;
    /**
     * Elliptic curve.
     */
    private ECCurve curve;
    /**
     * Base point (generator) G of the elliptic curve.
     */
    private ECPoint base;
    /**
     * Order n of the base point - order of the curve.
     */
    private byte[] order;
    /**
     * Cofactor h of the elliptic curve.
     */
    private byte[] cofactor;
    /**
     * Degree of the Characteristic-2 field F2^m.
     */
    private short m;
    /**
     * Type of the basis.
     */
    private EECBasisType basis;
    /**
     * Exponent k of the trinomial form x^m + x^k + 1.
     */
    private byte[] k;
    /**
     * Exponent k1 of the pentanomial form x^m + x^k3 + x^k2 + x^k1 + 1.
     */
    private byte[] k1;
    /**
     * Exponent k2 of the pentanomial form x^m + x^k3 + x^k2 + x^k1 + 1.
     */
    private byte[] k2;
    /**
     * Exponent k3 of the pentanomial form x^m + x^k3 + x^k2 + x^k1 + 1.
     */
    private byte[] k3;
    /**
     * Named curve.
     */
    private ENamedCurve namedCurve;

    /**
     * Initializes an EC Parameters part as defined in RFC 4492.
     */
    public ECParameters() {
    }

    /**
     * Initializes an EC Parameters part as defined in RFC 4492.
     *
     * @param message EC Parameters part in encoded form
     */
    public ECParameters(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the curve type value of this message.
     *
     * @return The prime curve type value of this message
     */
    public EECCurveType getCurveType() {
        return EECCurveType.valueOf(curveType.name());
    }

    /**
     * Set the curve type value of this message part.
     *
     * @param curveType The curve type value to be used for this message part
     */
    public void setCurveType(final EECCurveType curveType) {
        this.curveType = EECCurveType.valueOf(curveType.name());
    }

    /**
     * Get the prime p value of this message.
     *
     * @return The prime p value of this message
     */
    public byte[] getPrimeP() {
        // deep copy
        byte[] tmp = new byte[primeP.length];
        System.arraycopy(primeP, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the prime p value of this message part.
     *
     * @param primeP The prime p value to be used for this message part
     */
    public void setPrimeP(final byte[] primeP) {
        if (primeP == null) {
            throw new IllegalArgumentException("Prime p value "
                    + "must not be null!");
        }

        // deep copy
        this.primeP = new byte[primeP.length];
        System.arraycopy(primeP, 0, this.primeP, 0, primeP.length);
    }

    /**
     * Get the curve value of this message.
     *
     * @return The curve value of this message
     */
    public ECCurve getCurve() {
        return new ECCurve(curve.encode(false));
    }

    /**
     * Set the curve value of this message part.
     *
     * @param curve The curve value to be used for this message part
     */
    public void setCurve(final ECCurve curve) {
        this.curve = new ECCurve(curve.encode(false));
    }

    /**
     * Get the base value of this message.
     *
     * @return The base value of this message
     */
    public ECPoint getBase() {
        return new ECPoint(base.encode(false));
    }

    /**
     * Set the base value of this message part.
     *
     * @param base The base value to be used for this message part
     */
    public void setBase(final ECPoint base) {
        this.base = new ECPoint(base.encode(false));
    }

    /**
     * Get the order value of this message.
     *
     * @return The order value of this message
     */
    public byte[] getOrder() {
        // deep copy
        byte[] tmp = new byte[order.length];
        System.arraycopy(order, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the order value of this message part.
     *
     * @param order The order value to be used for this message part
     */
    public void setOrder(final byte[] order) {
        if (order == null) {
            throw new IllegalArgumentException("Order value "
                    + "must not be null!");
        }

        // deep copy
        this.order = new byte[order.length];
        System.arraycopy(order, 0, this.order, 0, order.length);
    }

    /**
     * Get the cofactor value of this message.
     *
     * @return The cofactor value of this message
     */
    public byte[] getCofactor() {
        // deep copy
        byte[] tmp = new byte[cofactor.length];
        System.arraycopy(cofactor, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the cofactor value of this message part.
     *
     * @param cofactor The cofactor value to be used for this message part
     */
    public void setCofactor(final byte[] cofactor) {
        if (cofactor == null) {
            throw new IllegalArgumentException("Cofactor value "
                    + "must not be null!");
        }

        // deep copy
        this.cofactor = new byte[cofactor.length];
        System.arraycopy(cofactor, 0, this.cofactor, 0, cofactor.length);
    }

    /**
     * Get the m value of this message.
     *
     * @return The m value of this message
     */
    public short getM() {
        return this.m;
    }

    /**
     * Set the m value of this message part.
     *
     * @param m The m value to be used for this message part
     */
    public void setM(final short m) {
        this.m = m;
    }

    /**
     * Get the basis value of this message.
     *
     * @return The basis value of this message
     */
    public EECBasisType getBasis() {
        return EECBasisType.valueOf(basis.name());
    }

    /**
     * Set the basis value of this message part.
     *
     * @param basis The basis value to be used for this message part
     */
    public void setBasis(final EECBasisType basis) {
        this.basis = EECBasisType.valueOf(basis.name());
    }

    /**
     * Get the k value of this message.
     *
     * @return The k value of this message
     */
    public byte[] getK() {
        // deep copy
        byte[] tmp = new byte[k.length];
        System.arraycopy(k, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the k value of this message part.
     *
     * @param k The k value to be used for this message part
     */
    public void setK(final byte[] k) {
        if (k == null) {
            throw new IllegalArgumentException("K value "
                    + "must not be null!");
        }

        // deep copy
        this.k = new byte[k.length];
        System.arraycopy(k, 0, this.k, 0, k.length);
    }

    /**
     * Get the k value of this message.
     *
     * @return The k value of this message
     */
    public byte[] getK1() {
        // deep copy
        byte[] tmp = new byte[k1.length];
        System.arraycopy(k1, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the k1 value of this message part.
     *
     * @param k1 The k1 value to be used for this message part
     */
    public void setK1(final byte[] k1) {
        if (k1 == null) {
            throw new IllegalArgumentException("K1 value "
                    + "must not be null!");
        }

        // deep copy
        this.k1 = new byte[k1.length];
        System.arraycopy(k1, 0, this.k1, 0, k1.length);
    }

    /**
     * Get the k2 value of this message.
     *
     * @return The k2 value of this message
     */
    public byte[] getK2() {
        // deep copy
        byte[] tmp = new byte[k2.length];
        System.arraycopy(k2, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the k2 value of this message part.
     *
     * @param k2 The k2 value to be used for this message part
     */
    public void setK2(final byte[] k2) {
        if (k2 == null) {
            throw new IllegalArgumentException("K2 value "
                    + "must not be null!");
        }

        // deep copy
        this.k2 = new byte[k2.length];
        System.arraycopy(k2, 0, this.k2, 0, k2.length);
    }

    /**
     * Get the k3 value of this message.
     *
     * @return The k3 value of this message
     */
    public byte[] getK3() {
        // deep copy
        byte[] tmp = new byte[k3.length];
        System.arraycopy(k3, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the k3 value of this message part.
     *
     * @param k3 The k3 value to be used for this message part
     */
    public void setK3(final byte[] k3) {
        if (k3 == null) {
            throw new IllegalArgumentException("K3 value "
                    + "must not be null!");
        }

        // deep copy
        this.k3 = new byte[k3.length];
        System.arraycopy(k3, 0, this.k3, 0, k3.length);
    }

    /**
     * Get the named curve value of this message.
     *
     * @return The named curve value of this message
     */
    public ENamedCurve getNamedCurve() {
        return ENamedCurve.valueOf(namedCurve.name());
    }

    /**
     * Set the named curve value of this message part.
     *
     * @param namedCurve The namedCurve value to be used for this message part
     */
    public void setNamedCurve(final ENamedCurve namedCurve) {
        this.namedCurve = ENamedCurve.valueOf(namedCurve.name());
    }

    /**
     * {@inheritDoc}
     *
     * Chained parameter is ignored - no chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] ecParameters = null;
        byte[] tmp;

        switch (curveType) {
            case EXPLICIT_PRIME:
                tmp = encodeExplicitPrime();
                break;
            case EXPLICIT_CHAR2:
                tmp = encodeExplicitChar2();
                break;
            case NAMED_CURVE:
                tmp = namedCurve.getId();
                break;
            default:
                throw new IllegalArgumentException("Illegal curve type.");
        }
        ecParameters = new byte[EECCurveType.LENGTH_ENCODED + tmp.length];
        ecParameters[0] = curveType.getId();
        System.arraycopy(tmp, 0, ecParameters, EECCurveType.LENGTH_ENCODED,
                tmp.length);

        return ecParameters;
    }

    /**
     * {@inheritDoc} Chained parameter is ignored - no chained decoding.
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] tmp;
        // deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);

        int pointer = 0;
        // 1. extract curve type
        tmp = new byte[EECCurveType.LENGTH_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setCurveType(EECCurveType.getECCurveType(tmp[0]));
        pointer += tmp.length;

        switch (curveType) {
            case EXPLICIT_PRIME:
                decodeExplicitPrime(paramCopy, pointer);
                break;
            case EXPLICIT_CHAR2:
                decodeExplicitChar2(paramCopy, pointer);
                break;
            case NAMED_CURVE:
                tmp = new byte[ENamedCurve.LENGTH_ENCODED];
                System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
                setNamedCurve(ENamedCurve.getNamedCurve(tmp));
                pointer += tmp.length;
                break;
            default:
                throw new IllegalArgumentException("Illegal curve type.");
        }

    }

    private void decodeExplicitPrime(final byte[] paramCopy, int offset) {
        int pointer = offset;
        int extractedLength;
        byte[] tmp;

        // extract prime p
        extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_PRIME_P);
        tmp = new byte[extractedLength];
        pointer += LENGTH_FIELD_PRIME_P;
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setPrimeP(tmp);
        pointer += tmp.length;

        // extract curve
        tmp = new byte[ECCurve.LENGTH_MINIMUM_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setCurve(new ECCurve(tmp));
        pointer += tmp.length;

        // extract base
        tmp = new byte[ECPoint.LENGTH_MINIMUM_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setBase(new ECPoint(tmp));
        pointer += tmp.length;

        // extract order
        extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_ORDER);
        tmp = new byte[extractedLength];
        pointer += LENGTH_FIELD_ORDER;
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setOrder(tmp);
        pointer += tmp.length;

        // extract cofactor
        extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_COFACTOR);
        tmp = new byte[extractedLength];
        pointer += LENGTH_FIELD_COFACTOR;
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setCofactor(tmp);
        pointer += tmp.length;
    }

    private void decodeExplicitChar2(final byte[] paramCopy, int offset) {
        int pointer = offset;
        int extractedLength;
        byte[] tmp;

        // extract m
        tmp = new byte[LENGTH_M];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setM(Utility.bytesToShort(tmp));
        pointer += tmp.length;

        // extract m
        tmp = new byte[EECBasisType.LENGTH_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setBasis(EECBasisType.getECBasisType(tmp[0]));
        pointer += tmp.length;

        switch (getBasis()) {
            case EC_BASIS_TRINOMIAL:
                // extract k
                extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_K);
                tmp = new byte[extractedLength];
                pointer += LENGTH_FIELD_K;
                System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
                setK(tmp);
                pointer += tmp.length;
                break;
            case EC_BASIS_PENTANOMIAL:
                // extract k1
                extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_K1);
                tmp = new byte[extractedLength];
                pointer += LENGTH_FIELD_K1;
                System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
                setK1(tmp);
                pointer += tmp.length;
                // extract k2
                extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_K2);
                tmp = new byte[extractedLength];
                pointer += LENGTH_FIELD_K2;
                System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
                setK2(tmp);
                pointer += tmp.length;
                // extract k3
                extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_K3);
                tmp = new byte[extractedLength];
                pointer += LENGTH_FIELD_K3;
                System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
                setK3(tmp);
                pointer += tmp.length;
                break;
            default:
                throw new IllegalArgumentException("Illegal Basis Type.");
        }

        // extract curve
        tmp = new byte[ECCurve.LENGTH_MINIMUM_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setCurve(new ECCurve(tmp));
        pointer += tmp.length;

        // extract base
        tmp = new byte[ECPoint.LENGTH_MINIMUM_ENCODED];
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setBase(new ECPoint(tmp));
        pointer += tmp.length;

        // extract order
        extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_ORDER);
        tmp = new byte[extractedLength];
        pointer += LENGTH_FIELD_ORDER;
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setOrder(tmp);
        pointer += tmp.length;

        // extract cofactor
        extractedLength = extractLength(paramCopy, 0, LENGTH_FIELD_COFACTOR);
        tmp = new byte[extractedLength];
        pointer += LENGTH_FIELD_COFACTOR;
        System.arraycopy(paramCopy, pointer, tmp, 0, tmp.length);
        setCofactor(tmp);
        pointer += tmp.length;
    }

    /**
     * Encodes the EC parameters if an explicit prime type is used.
     *
     * @return Encoded parameters
     */
    private byte[] encodeExplicitPrime() {
        int pointer = 0;
        byte[] tmp;
        byte[] ecParameters = new byte[EECCurveType.LENGTH_ENCODED
                + primeP.length + ECCurve.LENGTH_MINIMUM_ENCODED
                + curve.getA().length + curve.getB().length
                + ECPoint.LENGTH_MINIMUM_ENCODED
                + base.getPoint().length - 1 // 1 already in MINIMUM_ENC
                + LENGTH_FIELD_ORDER + order.length
                + LENGTH_FIELD_COFACTOR + cofactor.length];

        /*
         * 1. add curve type
         */
        tmp = new byte[]{curveType.getId()};
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 2. add prime p length
         */
        tmp = buildLength(primeP.length, LENGTH_FIELD_PRIME_P);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 3. add prime p
         */
        tmp = getPrimeP();
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 4. add curve
         */
        tmp = curve.encode(false);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 5. add base
         */
        tmp = base.encode(false);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 6. add order length
         */
        tmp = buildLength(order.length, LENGTH_FIELD_ORDER);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 7. add order
         */
        tmp = getOrder();
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 8. add cofactor length
         */
        tmp = buildLength(cofactor.length, LENGTH_FIELD_COFACTOR);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 9. add cofactor
         */
        tmp = getCofactor();
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;

        return ecParameters;
    }

    /**
     * Encodes the EC parameters if an explicit characteristic-2 type is used.
     *
     * @return Encoded parameters
     */
    private byte[] encodeExplicitChar2() {
        int pointer = 0;
        byte[] tmp;
        byte[] ecParameters = new byte[LENGTH_M];

        /*
         * 1. m and basis type
         */
        tmp = new byte[LENGTH_M + EECBasisType.LENGTH_ENCODED];
        System.arraycopy(Utility.shortToBytes(m), 0, ecParameters, pointer,
                LENGTH_M);
        tmp[LENGTH_M] = getBasis().getId();
        /**
         * 3. add curve type specific values.
         */
        switch (basis) {
            case EC_BASIS_TRINOMIAL:
                ecParameters = new byte[tmp.length // m + basis type
                        + LENGTH_FIELD_K + k.length
                        + ECCurve.LENGTH_MINIMUM_ENCODED
                        + curve.getA().length + curve.getB().length
                        + ECPoint.LENGTH_MINIMUM_ENCODED
                        + base.getPoint().length - 1 // 1 already in MINIMUM_ENC
                        + LENGTH_FIELD_ORDER + order.length
                        + LENGTH_FIELD_COFACTOR + cofactor.length];
                // add m and basis type
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add length of k
                tmp = buildLength(k.length, LENGTH_FIELD_K);
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add k
                tmp = getK();
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;

                break;
            case EC_BASIS_PENTANOMIAL:
                ecParameters = new byte[tmp.length // m and basis type
                        + LENGTH_FIELD_K1 + k1.length
                        + LENGTH_FIELD_K2 + k2.length
                        + LENGTH_FIELD_K3 + k3.length
                        + ECCurve.LENGTH_MINIMUM_ENCODED
                        + curve.getA().length + curve.getB().length
                        + ECPoint.LENGTH_MINIMUM_ENCODED
                        + base.getPoint().length - 1 // 1 already in MINIMUM_ENC
                        + LENGTH_FIELD_ORDER + order.length
                        + LENGTH_FIELD_COFACTOR + cofactor.length];
                // add m and basis type
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                // add length of k1
                tmp = buildLength(k1.length, LENGTH_FIELD_K1);
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add k1
                tmp = getK1();
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add length of k2
                tmp = buildLength(k2.length, LENGTH_FIELD_K2);
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add k2
                tmp = getK2();
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add length of k3
                tmp = buildLength(k3.length, LENGTH_FIELD_K3);
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;
                // add k3
                tmp = getK3();
                System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
                pointer += tmp.length;

                break;
            default:
                throw new IllegalArgumentException("Illegal Basis Type.");
        }

        /*
         * 3. add curve
         */
        tmp = curve.encode(false);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 4. add base
         */
        tmp = base.encode(false);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 5. add order length
         */
        tmp = buildLength(order.length, LENGTH_FIELD_ORDER);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 6. add order
         */
        tmp = getOrder();
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 7. add cofactor length
         */
        tmp = buildLength(cofactor.length, LENGTH_FIELD_COFACTOR);
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;
        /*
         * 8. add cofactor
         */
        tmp = getCofactor();
        System.arraycopy(tmp, 0, ecParameters, pointer, tmp.length);
        pointer += tmp.length;

        return ecParameters;
    }
}
