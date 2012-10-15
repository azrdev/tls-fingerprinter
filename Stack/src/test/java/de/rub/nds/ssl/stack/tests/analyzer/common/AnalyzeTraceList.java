package de.rub.nds.ssl.stack.tests.analyzer.common;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.trace.Message;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.ArrayList;

/**
 * Utilities for trace list analysis.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Aug 02, 2012
 */
public class AnalyzeTraceList {

    /**
     * Get the alert message from the trace list and extract the alert
     * description.
     *
     * @param traceList Trace list of a handshake
     * @return Alert description
     */
    public final String getAlertFromTraceList(
            final ArrayList<Message> traceList) {
        String alertDesc = null;
        for (int i = 0; i < traceList.size(); i++) {
            Message currentTrace = traceList.get(i);
            if (currentTrace.getState() == EStates.ALERT) {
                Alert alert = (Alert) currentTrace.getCurrentRecord();
                alertDesc = alert.getAlertDescription().name();
            }
        }
        return alertDesc;
    }

    /**
     * Get the alert description from a single trace.
     *
     * @param trace Trace
     * @return Alert description
     */
    public final String getAlertDescFromTrace(final Message trace) {
        Alert alert = (Alert) trace.getCurrentRecord();
        return alert.getAlertDescription().name();
    }

    /**
     * Get the last trace of a trace list.
     *
     * @param traceList Trace list of a handshake
     * @return Last trace
     */
    public final Message getLastTrace(
            final ArrayList<Message> traceList) {
        return traceList.get(traceList.size() - 1);
    }
}
