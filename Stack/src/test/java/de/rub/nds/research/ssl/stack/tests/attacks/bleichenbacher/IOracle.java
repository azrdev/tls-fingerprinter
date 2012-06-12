package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import java.security.PublicKey;

/**
 * Oracle Interface for Bleichenbacher attack.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 12, 2012
 */
public interface IOracle {

    /**
     * Checks for PKCS conformity - 00 02 padding 00 pms
     * @param msg Encrypted message to check for conformity
     * @return True if PKCS conforming, else false 
     */
    boolean checkPKCSConformity(final byte[] msg);

    /**
     * Gets the blocksize of the encryption algorithm.
     * @return Blocksize
     */
    int getBlockSize();

    /**
     * Gets the total number of queries performed by this oracle.
     * @return Number of queries
     */
    long getNumberOfQueries();

    /**
     * Gets the public key of this oracle.
     * @return Public key
     */
    PublicKey getPublicKey();
}
