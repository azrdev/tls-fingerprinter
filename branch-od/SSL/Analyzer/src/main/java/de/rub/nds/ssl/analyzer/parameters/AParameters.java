package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import java.security.MessageDigest;

/**
 * Test Parameters for fingerprint analysis.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 26, 2012
 */
public abstract class AParameters implements Cloneable {

    /**
     * Test class identifier.
     */
    private EFingerprintTests id;
    /**
     * Description of the test case.
     */
    private String desc;

    /**
     * Get the identifier of a fingerprinting test case.
     *
     * @return Test case identifier
     */
    public final EFingerprintTests getIdentifier() {
        return EFingerprintTests.valueOf(this.id.name());
    }

    /**
     * Set the identifier of a fingerprinting test case.
     *
     * @param id Test case identifier
     */
    public final void setIdentifier(final EFingerprintTests id) {
        this.id = EFingerprintTests.valueOf(id.name());
    }

    /**
     * Get the description of a test case.
     *
     * @return Description of the test case
     */
    public final String getDescription() {
        return this.desc;
    }

    /**
     * Set the description of a test case.
     *
     * @param desc Decription of the test case
     */
    public final void setDescription(final String desc) {
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

    /**
     * {@inheritDoc}
     */
    @Override
    public final AParameters clone() throws CloneNotSupportedException {
        return (AParameters) super.clone();
    }
}
