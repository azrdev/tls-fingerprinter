package de.rub.nds.ssl.stack.tests.analyzer;

import java.util.ArrayList;

import de.rub.nds.ssl.stack.tests.trace.MessageTrace;

/**
 * Fingerprint analysis of a Unit Test.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * May 26, 2012
 */
public abstract class AFingerprintAnalyzer {
	
	/**
	 * Match a fingerprint using the test trace.
	 * @param traceList MessageTrace list of a testrun
	 */
	public abstract void analyze(ArrayList<MessageTrace> traceList);

}
