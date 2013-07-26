package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.handshake.MessageObservable;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.IGenericCipher;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import java.util.Arrays;
import java.util.Observable;
import java.util.Observer;
import org.apache.log4j.Logger;

/**
 * A response during the TLS protocol processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 15, 2012
 */
public final class TLSResponse extends ARecordFrame implements Observer {
// TODO: Ugly and confusing class! Needs to be corrected!

    /**
     * Current trace.
     */
    private MessageContainer trace;
    /**
     * Handshake workflow.
     */
    private TLS10HandshakeWorkflow workflow;
    /**
     * Response bytes.
     */
    private byte[] response;
    /**
     * Log4j logger.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Initialize a TLS response.
     *
     * @param response Bytes of the received response
     * @param workflow Workflow
     */
    public TLSResponse(final byte[] response,
            final TLS10HandshakeWorkflow workflow) {
        super(response);
        this.workflow = workflow;
        this.response = new byte[response.length];
        System.arraycopy(response, 0, this.response, 0, this.response.length);
    }

    /**
     * Extracts the TLS record messages for the response bytes.
     *
     * @param trace MessageContainer object to save the status
     */
    public final void handleResponse(final MessageContainer trace) {
        MessageObservable msgObserve = MessageObservable.getInstance();
        EContentType contentType = getContentType();
        switch (contentType) {
            case CHANGE_CIPHER_SPEC:
                logger.debug("Change Cipher Spec message received");
                ChangeCipherSpec ccs = new ChangeCipherSpec(response, true);
                trace.setCurrentRecord(ccs);
                trace.setPreviousState(EStates.getStateById(workflow.
                        getCurrentState()));
                workflow.switchToState(trace,
                        EStates.SERVER_CHANGE_CIPHER_SPEC);
                trace.setState(EStates.getStateById(
                        workflow.getCurrentState()));
                workflow.addToTraceList(trace);
                break;
            case ALERT:
                logger.debug("Alert message received");
                Alert alert = new Alert(response, true);
                logger.debug("Alert level: " + alert.getAlertLevel().name());
                logger.debug("Alert message: " + alert.getAlertDescription().
                        name());
                trace.setCurrentRecord(alert);
                trace.setPreviousState(EStates.getStateById(workflow.
                        getCurrentState()));
                if (EAlertLevel.FATAL.equals(alert.getAlertLevel())) {
                    workflow.switchToState(trace, EStates.ALERT);
                } else {
                    workflow.nextStateAndNotify(trace);
                }
                trace.setState(EStates.getStateById(
                        workflow.getCurrentState()));
                workflow.addToTraceList(trace);
                break;
            case HANDSHAKE:
                if (workflow.isEncrypted()) {
// TODO fix this code!                    
                    /*
                     * Since it is not possible to send CCS and Finished in a
                     * handhsake enumeration it is safe to distinguish this way
                     */
                    TLSCiphertext ciphertext = new TLSCiphertext(response,
                            true);
                    
                    trace.setCurrentRecord(ciphertext);
                    trace.setPreviousState(EStates.getStateById(workflow.
                            getCurrentState()));
                    workflow.nextStateAndNotify(trace);
                    trace.setState(EStates.getStateById(
                            workflow.getCurrentState()));
                    workflow.addToTraceList(trace);         
                    
                    MessageBuilder builder = new MessageBuilder();
                    TLSPlaintext plaintext = builder.decryptRecord(ciphertext);
                    setTrace(trace);
                    msgObserve.addObserver(this);
//// TODO: WTF is this???
                    new HandshakeEnumeration(plaintext.encode(false), false,
                            KeyExchangeParams.getInstance().
                            getKeyExchangeAlgorithm());
                    msgObserve.deleteObservers();
                } else {
                    setTrace(trace);
                    msgObserve.addObserver(this);
// TODO: WTF is this???
                    new HandshakeEnumeration(response, true,
                            KeyExchangeParams.getInstance().
                            getKeyExchangeAlgorithm());
                    msgObserve.deleteObservers();
                }
                break;
            default:
                break;
        }
    }

    /**
     * Set the trace for the handshake message.
     *
     * @param trace MessageContainer
     */
    private void setTrace(final MessageContainer trace) {
        this.trace = trace;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void update(final Observable o, final Object arg) {
        MessageContainer newTrace = new MessageContainer();
        newTrace.setTimestamp(this.trace.getTimestamp());
        AHandshakeRecord handRecord = null;
        if (o instanceof MessageObservable) {
            handRecord = (AHandshakeRecord) arg;
            HandshakeResponse.invokeMessageHandlers(handRecord, newTrace,
                    workflow);
            setTrace(newTrace);
        }
        if (handRecord != null) {
            int recordSize = handRecord.getPayload().length
                    + AHandshakeRecord.LENGTH_MINIMUM_ENCODED
                    + ARecordFrame.LENGTH_MINIMUM_ENCODED;
            if (recordSize < this.response.length) {
                newTrace.setContinued(true);
            }
        }
        newTrace.setState(EStates.getStateById(workflow.getCurrentState()));
        workflow.addToTraceList(newTrace);
    }
}
