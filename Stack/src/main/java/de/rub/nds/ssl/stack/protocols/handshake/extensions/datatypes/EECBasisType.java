package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

/**
 * EC Basis Types for characteristic-2 fields as defined in RFC 4492.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 30, 2013
 */
public enum EECBasisType {
    /**
     * Trionomial basis representation.
     */
    EC_BASIS_TRINOMIAL,
    /**
     * Pentanomial basis representation.
     */
    EC_BASIS_PENTANOMIAL;
}
