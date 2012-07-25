package de.rub.nds.ssl.stack.tests.analyzer.parameters;

import java.security.MessageDigest;

/**
 * Test Parameters for fingerprint analysis.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de May 26, 2012
 */
public abstract class AParameters {

    /**
     * Test class name.
     */
    private String name;
    /**
     * Description of the test case
     */
    private String desc;

    /**
     * Get the name of the test class.
     *
     * @return Test class name
     */
    public String getTestClassName() {
        return this.name;
    }

    /**
     * Set the name of the test class.
     *
     * @param className Test class name
     */
    public void setTestClassName(String className) {
        this.name = className;
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
