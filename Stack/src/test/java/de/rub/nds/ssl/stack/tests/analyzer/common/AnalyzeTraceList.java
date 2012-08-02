package de.rub.nds.ssl.stack.tests.analyzer.common;

import java.util.ArrayList;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.tests.trace.Trace;
import de.rub.nds.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;

public class AnalyzeTraceList {
	
	public String getAlertFromTraceList(ArrayList<Trace> traceList) {
		String alertDesc = null;
        for (int i = 0; i < traceList.size(); i++) {
            Trace currentTrace = traceList.get(i);
            if (currentTrace.getState() == EStates.ALERT) {
                Alert alert = (Alert) currentTrace.getCurrentRecord();
                alertDesc = alert.getAlertDescription().name();
            }
        }
        return alertDesc;
	}
	
	public String getAlertDescFromTrace(Trace trace) {
		Alert alert = (Alert)trace.getCurrentRecord();
		return alert.getAlertDescription().name();
	}
	
	public Trace getLastTrace(ArrayList<Trace> traceList) {
		return traceList.get(traceList.size() -1);
	}

}
