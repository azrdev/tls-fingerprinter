package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.security.MessageDigest;

/**
 * Test Parameters for fingerprint analysis.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * May 26, 2012
 */
public abstract class AParameters {
	
	/**
	 * Compute the hash value of the test parameters.
	 * @return Hash value as a String
	 */
	public abstract String computeHash();
	
	/**
	 * Update the hash value.
	 * @param md Hash function
	 * @param input Hash input
	 */
	public abstract void updateHash(MessageDigest md, byte [] input);

}
