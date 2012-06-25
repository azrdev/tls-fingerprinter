package de.rub.nds.research.ssl.stack.tests.response;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.research.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.research.ssl.stack.protocols.handshake.MessageObservable;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;

/**
 * A response during the SSL protocol processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 15, 2012
 */
public class SSLResponse extends ARecordFrame implements Observer {

    /**
     * Current trace
     */
    private Trace trace;
    /**
     * Handshake workflow
     */
    private SSLHandshakeWorkflow workflow;
    
    static Logger logger = Logger.getLogger(SSLResponse.class.getName());

    /**
     * Initialize a SSL response.
     *
     * @param response Bytes of the received response
     */
    public SSLResponse(final byte[] response,
            SSLHandshakeWorkflow workflow) {
        super(response);
        this.workflow = workflow;
    }

    /**
     * Extracts the SSL record messages for the response bytes.
     *
     * @param trace Trace object to save the status
     * @param response Bytes of the received response
     * @param param Security parameters as defined in Chapter 6.1 of RFC 2246
     * @return ResponseHandler
     */
    public final void handleResponse(final Trace trace,
            final byte[] response) {
        MessageObservable msgObserve = MessageObservable.getInstance();
        EContentType contentType = getContentType();
        switch (contentType) {
            case CHANGE_CIPHER_SPEC:
            	logger.info("Change Cipher Spec message received");
                ChangeCipherSpec ccs = new ChangeCipherSpec(response, true);
                trace.setCurrentRecord(ccs);
                workflow.switchToState(trace, EStates.SERVER_CHANGE_CIPHER_SPEC);
                trace.setState(EStates.getStateById(workflow.getCurrentState()));
                workflow.addToList(trace);
                break;
            case ALERT:
            	logger.info("Alert message received");
                Alert alert = new Alert(response, true);
                logger.info("Alert level: " + alert.getAlertLevel().name());
                logger.info("Alert message: " + alert.getAlertDescription().name());
                trace.setCurrentRecord(alert);
                if (EAlertLevel.FATAL.equals(alert.getAlertLevel())) {
                    workflow.switchToState(trace, EStates.ALERT);
                } else {
                    workflow.switchToNextState(trace);
                }
                trace.setState(EStates.getStateById(workflow.getCurrentState()));
                workflow.addToList(trace);
                break;
            case HANDSHAKE:
                if (workflow.isEncrypted()) {
                	logger.info("Finished message received");
                    TLSCiphertext ciphertext = new TLSCiphertext(response, true);
                    trace.setCurrentRecord(ciphertext);
                    workflow.switchToNextState(trace);
                    trace.setState(EStates.getStateById(
                            workflow.getCurrentState()));
                    workflow.addToList(trace);
                } else {
                    setTrace(trace);
                    msgObserve.addObserver(this);
                    new HandshakeEnumeration(response, true);
                    msgObserve.deleteObservers();
                }
                break;
            default:
                break;
        }
    }

    /**
     * Set the trace for the handshake message
     *
     * @param trace Trace
     */
    private void setTrace(Trace trace) {
        this.trace = trace;
    }

    @Override
    public void update(Observable o, Object arg) {
        Trace trace = new Trace();
        trace.setNanoTime(this.trace.getNanoTime());
        trace.setTimestamp(this.trace.getTimestamp());
        AHandshakeRecord handRecord;
        if (o instanceof MessageObservable) {
            handRecord = (AHandshakeRecord) arg;
            new HandshakeResponse(handRecord, trace, workflow);
            setTrace(trace);
        }
        trace.setState(EStates.getStateById(workflow.getCurrentState()));
        workflow.addToList(trace);
    }
}
