package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.util.ArrayList;

import de.rub.nds.research.ssl.stack.tests.trace.Trace;

public class TraceListAnalyzer {
	
	public TraceListAnalyzer() {
		
	}
	
	public void analyzeList(ArrayList<Trace> traceList) {
		for (int i=0; i<traceList.size(); i++) {
			if (traceList.get(i).getOldRecord() != null) {
			}
		}
	}

}
