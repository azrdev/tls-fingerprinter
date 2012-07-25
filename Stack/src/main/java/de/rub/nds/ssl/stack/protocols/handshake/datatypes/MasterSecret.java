package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.PseudoRandomFunction;
import java.security.InvalidKeyException;

/**
 * MasterSecret part - as defined in RFC-2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Feb 16, 2012
 */
public class MasterSecret extends APubliclySerializable {

    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = 48;
    /**
     * Master secret label.
     */
    private static final String MASTER_SECRET_LABEL = "master secret";
    /**
     * Master secret bytes.
     */
    private byte[] masterSecret = null;

    /**
     * Initializes and computes the master secret.
     *
     * @param clientRandom Random value from the ClientHello message
     * @param serverRandom Random value from the ServerHello message
     * @param encodedPMS PreMasterSecret in encoded form
     * @throws InvalidKeyException Invalid key passed
     */
    public MasterSecret(final byte[] clientRandom,
            final byte[] serverRandom, final byte[] encodedPMS)
            throws InvalidKeyException {
        byte[] randomValues =
                this.concatRandomValues(clientRandom, serverRandom);
        PseudoRandomFunction prf = new PseudoRandomFunction(
                LENGTH_MINIMUM_ENCODED);
        masterSecret = prf.generatePseudoRandomValue(encodedPMS,
                MASTER_SECRET_LABEL, randomValues);
    }

    /**
     * Creates the seed value which is an input parameter of the PRF function.
     *
     * @param clientRandom Random value from the ClientHello message
     * @param serverRandom Random value from the ServerHello message
     * @return seed Concatenated client and server random
     */
    private byte[] concatRandomValues(final byte[] clientRandom,
            final byte[] serverRandom) {
        byte[] seed = new byte[clientRandom.length + serverRandom.length];
        int pointer = 0;
        //copy the client random to the array
        System.arraycopy(clientRandom, 0, seed, pointer, clientRandom.length);
        pointer += clientRandom.length;
        System.arraycopy(serverRandom, 0, seed, pointer, serverRandom.length);
        return seed;
    }

    /**
     * Set the bytes of the master secret.
     *
     * @param secretBytes The bytes of the master secret
     */
    public final void setMasterSecret(final byte[] secretBytes) {
        if (masterSecret == null
                || masterSecret.length != LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Master secret"
                    + "must be exactly 48 Bytes "
                    + LENGTH_MINIMUM_ENCODED + " bytes!");
        }
        // deep copy
        System.arraycopy(secretBytes, 0, masterSecret, 0, secretBytes.length);
    }

    /**
     * Get the master secret.
     *
     * @return Master secret
     */
    public final byte[] getMasterSecret() {
        // deep copy
        byte[] copy = new byte[LENGTH_MINIMUM_ENCODED];
        System.arraycopy(masterSecret, 0, copy, 0, LENGTH_MINIMUM_ENCODED);
        return copy;
    }

    /**
     * {@inheritDoc}
     *
     * Encrypted pre_master_secret.
     */
    @Override
    public final byte[] encode(final boolean chained) {
        byte[] masterSec = new byte[LENGTH_MINIMUM_ENCODED];
        System.arraycopy(masterSec, 0, masterSec, 0, masterSec.length);
        return masterSec;
    }

    @Override
    public void decode(final byte[] message, final boolean chained) {
        // TODO Auto-generated method stub
    }
}
