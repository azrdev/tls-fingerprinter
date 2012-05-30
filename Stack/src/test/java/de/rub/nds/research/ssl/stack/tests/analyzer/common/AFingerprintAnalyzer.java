package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.util.ArrayList;

import de.rub.nds.research.ssl.stack.tests.trace.Trace;

/**
 * Fingerprint analysis of a Unit Test.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * May 26, 2012
 */
public abstract class AFingerprintAnalyzer {
	
	/**
	 * Match a fingerprint using the test trace.
	 * @param traceList Trace list of a testrun
	 */
	public abstract void analyze(ArrayList<Trace> traceList);

}
