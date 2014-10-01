package de.rub.nds.ssl.stack.protocols.commons;

/**
 * MAC algorithm used for message authentication.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 09, 2012
 */
public enum EMACAlgorithm {
    //TODO: EMACAlgorithm duplicate of EHashAlgorithm ?

    /**
     * MD5 MAC.
     */
    MD5,
    /**
     * SHA1 MAC.
     */
    SHA1;
}
