package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

/**
 * Key exchange algorithm as used in the key exchange messages.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Jan 10, 2012
 */
public enum EKeyExchangeAlgorithm {

    //TODO: support all values of KeyExchangeAlgorithm: dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa

    /**
     * RSA key exchange.
     */
    RSA,
    /**
     * Diffie-Hellman key exchange.
     */
    DIFFIE_HELLMAN,
    /**
     * Diffie-Hellman elliptic curve key exchange.
     */
    EC_DIFFIE_HELLMAN,
}
