package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.handshake.MessageObservable;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.trace.MessageTrace;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.Observable;
import java.util.Observer;
import org.apache.log4j.Logger;

/**
 * A response during the TLS protocol processing.
 * 
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 15, 2012
 */
public class TLSResponse extends ARecordFrame implements Observer {
// TODO: Ugly and confusing class! Needs to be corrected!
    
    /**
     * Current trace.
     */
    private MessageTrace trace;
    /**
     * Handshake workflow.
     */
    private TLS10HandshakeWorkflow workflow;
    /**
     * Response bytes.
     */
    private byte[] response;
    static Logger logger = Logger.getRootLogger();

    /**
     * Initialize a TLS response.
     *
     * @param response Bytes of the received response
     * @param workflow Workflow 
     */
    public TLSResponse(final byte[] response,
            TLS10HandshakeWorkflow workflow) {
        super(response);
        this.workflow = workflow;
        this.response = new byte[response.length];
        System.arraycopy(response, 0, this.response, 0, this.response.length);
    }

    /**
     * Extracts the TLS record messages for the response bytes.
     *
     * @param trace MessageTrace object to save the status
     * @param param Security parameters as defined in Chapter 6.1 of RFC 2246
     * @return ResponseHandler
     */
    public final void handleResponse(final MessageTrace trace) {
        MessageObservable msgObserve = MessageObservable.getInstance();
        EContentType contentType = getContentType();
        switch (contentType) {
            case CHANGE_CIPHER_SPEC:
                logger.debug("Change Cipher Spec message received");
                ChangeCipherSpec ccs = new ChangeCipherSpec(response, true);
                trace.setCurrentRecord(ccs);
                workflow.switchToState(trace, EStates.SERVER_CHANGE_CIPHER_SPEC);
                trace.setState(EStates.getStateById(workflow.getCurrentState()));
                workflow.addToTraceList(trace);
                break;
            case ALERT:
                logger.debug("Alert message received");
                Alert alert = new Alert(response, true);
                logger.debug("Alert level: " + alert.getAlertLevel().name());
                logger.debug("Alert message: " + alert.getAlertDescription().
                        name());
                trace.setCurrentRecord(alert);
                if (EAlertLevel.FATAL.equals(alert.getAlertLevel())) {
                    workflow.switchToState(trace, EStates.ALERT);
                } else {
                    workflow.nextStateAndNotify(trace);
                }
                trace.setState(EStates.getStateById(workflow.getCurrentState()));
                workflow.addToTraceList(trace);
                break;
            case HANDSHAKE:
                if (workflow.isEncrypted()) {
                    logger.debug("Finished message received");
                    TLSCiphertext ciphertext = new TLSCiphertext(response, true);
                    trace.setCurrentRecord(ciphertext);
                    workflow.nextStateAndNotify(trace);
                    trace.setState(EStates.getStateById(
                            workflow.getCurrentState()));
                    workflow.addToTraceList(trace);
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
     * @param trace MessageTrace
     */
    private void setTrace(MessageTrace trace) {
        this.trace = trace;
    }

    @Override
    public void update(Observable o, Object arg) {
        MessageTrace trace = new MessageTrace();
        trace.setNanoTime(this.trace.getNanoTime());
        AHandshakeRecord handRecord = null;
        if (o instanceof MessageObservable) {
            handRecord = (AHandshakeRecord) arg;
            new HandshakeResponse(handRecord, trace, workflow);
            setTrace(trace);
        }
        if (handRecord != null) {
            int recordSize = handRecord.getPayload().length + AHandshakeRecord.LENGTH_MINIMUM_ENCODED
                    + ARecordFrame.LENGTH_MINIMUM_ENCODED;
            if (recordSize < this.response.length) {
                trace.setContinued(true);
            }
        }
        trace.setState(EStates.getStateById(workflow.getCurrentState()));
        workflow.addToTraceList(trace);
    }
}
