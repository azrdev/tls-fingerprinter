package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.util.ArrayList;

import de.rub.nds.research.ssl.stack.tests.trace.Trace;

public abstract class AFingerprintAnalyzer {
	
	public abstract void analyze(ArrayList<Trace> traceList);

}
