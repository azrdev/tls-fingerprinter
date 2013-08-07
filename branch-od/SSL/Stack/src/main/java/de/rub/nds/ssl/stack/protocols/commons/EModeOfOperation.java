package de.rub.nds.ssl.stack.protocols.commons;

/**
 * Mode of operation of a block cipher.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 29, 2012
 */
public enum EModeOfOperation {

    /**
     * CBC mode.
     */
    CBC,
    /**
     * GCM mode.
     */
    GCM;
}
