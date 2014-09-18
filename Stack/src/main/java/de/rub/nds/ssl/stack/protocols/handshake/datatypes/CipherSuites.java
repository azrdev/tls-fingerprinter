package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.exceptions.UnknownCipherSuiteException;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cipher suites part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 15, 2011
 */
public final class CipherSuites extends APubliclySerializable {

    private Logger logger = Logger.getLogger(getClass());

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * List of all cipher suites of this object.
     */
    private ECipherSuite[] suites = new ECipherSuite[0];

    /**
     * All cipher suites as raw byte ids, irrespective of whether a corresponding
     * ECipherSuite exists
     */
    private List<byte[]> rawSuites = new ArrayList<>(0);

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return Arrays.toString(suites);
    }

    /**
     * Initializes a cipher suites object as defined in RFC-2246.
     * All supported cipher suites are added by default at construction time.
     */
    public CipherSuites() {
        setSuites(ECipherSuite.values());
    }

    /**
     * Initializes a cipher suites object as defined in RFC-2246.
     *
     * @param message Cipher suites in encoded form
     */
    public CipherSuites(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the cipher suites of this message.
     *
     * @return The cipher suites of this message
     */
    public ECipherSuite[] getSuites() {
        // deep copy
        ECipherSuite[] tmp = new ECipherSuite[suites.length];
        System.arraycopy(suites, 0, tmp, 0, suites.length);

        return tmp;
    }

    /**
     * @return the raw suite "id"s of all CipherSuites
     */
    public List<byte[]> getRawSuites() {
        return rawSuites;
    }

    /**
     * Set the cipher suites of this message.
     *
     * @param suites The cipher suites to be used for this message
     */
    public void setSuites(final ECipherSuite[] suites) {
        setSuites(suites, true);
    }

    private void setSuites(final ECipherSuite[] suites, boolean setRaw) {
        if (suites == null) {
            throw new IllegalArgumentException("Suites must not be null!");
        }

        // new objects keep the array clean and small, Mr. Proper will be proud!
        this.suites = new ECipherSuite[suites.length];
        // refill, deep copy
        System.arraycopy(suites, 0, this.suites, 0, suites.length);

        if(setRaw) {
            this.rawSuites = new ArrayList<>(suites.length);
            for (ECipherSuite cs : suites) {
                rawSuites.add(cs.getId());
            }
        }
    }

    /**
     * {@inheritDoc} CipherSuites representation 2 + x*2 bytes for x cipher
     * suites.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        Integer cipherSuitesBytes = suites.length * ECipherSuite.LENGTH_ENCODED;
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + cipherSuitesBytes];
        byte[] tmpID;

        // length
        tmpID = buildLength(cipherSuitesBytes, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmpID, 0, tmp, pointer, tmpID.length);
        //pointer += tmpID.length;

        for (int i = 1; i - 1 < suites.length; i++) {
            tmpID = suites[i - 1].getId();
            tmp[i * ECipherSuite.LENGTH_ENCODED] = tmpID[0];
            tmp[i * ECipherSuite.LENGTH_ENCODED + 1] = tmpID[1];
        }

        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        rawSuites.clear();
        final int cipherSuitesCount;
        // deep copy
        final byte[] tmpSuites = new byte[message.length];
        System.arraycopy(message, 0, tmpSuites, 0, tmpSuites.length);

        // check size
        if (tmpSuites.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "Cipher suites record too short.");
        }
        cipherSuitesCount = (extractLength(tmpSuites, 0,
                LENGTH_LENGTH_FIELD) >> 1) & 0xff;

        if (tmpSuites.length - LENGTH_LENGTH_FIELD != cipherSuitesCount
                * ECipherSuite.LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "Cipher suites record length invalid.");
        }

        // extract cipher suites
        ECipherSuite[] cipherSuites = new ECipherSuite[cipherSuitesCount];
        for (int j = 0, i = LENGTH_LENGTH_FIELD; j < cipherSuitesCount;
                i += ECipherSuite.LENGTH_ENCODED, j++) {
            byte[] id = new byte[]{tmpSuites[i], tmpSuites[i + 1]};
            rawSuites.add(id);
            try {
                cipherSuites[j] = ECipherSuite.getCipherSuite(id);
            } catch(UnknownCipherSuiteException e) {
                logger.debug(e);
            }
        }
        setSuites(cipherSuites, false);
    }
}
