package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

/**
 * Key exchange algorithm as used in the key exchange messages.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jan 10, 2012
 */
public enum EKeyExchangeAlgorithm {

    /**
     * RSA key exchange.
     */
    RSA,
    /**
     * Diffie-Hellman key exchange.
     */
    DIFFIE_HELLMAN;
}
