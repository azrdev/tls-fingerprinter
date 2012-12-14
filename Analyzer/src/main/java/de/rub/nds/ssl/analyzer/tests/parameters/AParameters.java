package de.rub.nds.ssl.analyzer.tests.parameters;

import java.security.MessageDigest;


/**
 * Test Parameters for fingerprint analysis.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 26, 2012
 */
public abstract class AParameters {

    /**
     * Test class identifier.
     */
    private EFingerprintIdentifier id;
    /**
     * Description of the test case
     */
    private String desc;

    /**
     * Get the identifier of a fingerprinting test case.
     *
     * @return Test case identifier
     */
    public EFingerprintIdentifier getIdentifier() {
        return this.id;
    }

    /**
     * Set the identifier of a fingerprinting test case.
     *
     * @param id Test case identifier
     */
    public void setIdentifier(EFingerprintIdentifier id) {
        this.id = id;
    }

    /**
     * Get the description of a test case.
     *
     * @return Description of the test case
     */
    public String getDescription() {
        return this.desc;
    }

    /**
     * Set the description of a test case.
     *
     * @param desc Decription of the test case
     */
    public void setDescription(String desc) {
        this.desc = desc;
    }

    /**
     * Compute the hash value of the test parameters.
     *
     * @return Hash value as a String
     */
    public abstract String computeHash();

    /**
     * Update the hash value.
     *
     * @param md Hash function
     * @param input Hash input
     */
    public abstract void updateHash(MessageDigest md, byte[] input);
}
