package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.List;

/**
 * Utilities for trace list analysis.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Aug 02, 2012
 */
public final class TraceListAnalyzerUtility {

    /**
     * Get the alert message from the trace list and extract the alert
     * description.
     *
     * @param traceList Trace list of a handshake
     * @return Alert description
     */
    public static String getAlertFromTraceList(
            final List<MessageContainer> traceList) {
        String alertDesc = null;
        for (int i = 0; i < traceList.size(); i++) {
            MessageContainer currentTrace = traceList.get(i);
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
    public static String getAlertDescFromTrace(
            final MessageContainer trace) {
        Alert alert = (Alert) trace.getCurrentRecord();
        return alert.getAlertDescription().name();
    }

    /**
     * Get the last trace of a trace list.
     *
     * @param traceList Trace list of a handshake
     * @return Last trace
     */
    public static MessageContainer getLastTrace(
            final List<MessageContainer> traceList) {
        MessageContainer result = null;
        if(traceList.size() >= 1)  {
            result = traceList.get(traceList.size() - 1);
        }
        
        return result;
    }

    /**
     * Private constructor.
     */
    private TraceListAnalyzerUtility() {
    }
}
