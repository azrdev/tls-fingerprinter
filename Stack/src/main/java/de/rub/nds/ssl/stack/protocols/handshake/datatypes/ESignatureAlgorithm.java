package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

/**
 * Algorithm used for signing.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 10, 2012
 */
public enum ESignatureAlgorithm {

    /**
     * RSA signature.
     */
    RSA,
    /**
     * DSS signature.
     */
    DSS,
    /**
     * Anonymous.
     */
    anon,
    /**
     * ECDSA
     */
    ECDSA;
}
