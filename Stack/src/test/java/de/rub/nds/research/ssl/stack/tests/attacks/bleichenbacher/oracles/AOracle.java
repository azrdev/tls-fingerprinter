package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Oracle template for Bleichenbacher attack.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 12, 2012
 */
public abstract class AOracle {

    /* number of queries issued to oracle */
    protected long numberOfQueries;
    /* block size of the encryption algorithm */
    protected int blockSize;
    /* public key of the oracle */
    protected RSAPublicKey publicKey;
    
    /**
     * Gets the blocksize of the encryption algorithm.
     *
     * @return Blocksize
     */
    public int getBlockSize() {
        return this.blockSize;
    }

    /**
     * Gets the total number of queries performed by this oracle.
     *
     * @return Number of queries
     */
    public long getNumberOfQueries() {
        return this.numberOfQueries;
    }
    
    /**
     * Gets the public key of this oracle.
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Checks for PKCS conformity - 00 02 padding 00 pms
     *
     * @param msg Encrypted message to check for conformity
     * @return True if PKCS conforming, else false
     */
    public abstract boolean checkPKCSConformity(final byte[] msg);

}
