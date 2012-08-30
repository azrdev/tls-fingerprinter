package de.rub.nds.ssl.stack.tests.response;

import de.rub.nds.ssl.stack.protocols.handshake.*;
import de.rub.nds.ssl.stack.tests.trace.MessageTrace;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow.EStates;
import org.apache.log4j.Logger;

/**
 * Determine the handshake record in response and invoke the appropriate
 * handler.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 15, 2012
 */
public class HandshakeResponse {

    /**
     * Server hello state.
     */
    IHandshakeStates serverHello;
    /**
     * Certificate state.
     */
    IHandshakeStates certificate;
    /**
     * ServerKeyExchange state.
     */
    IHandshakeStates serverKeyExchange;
    static Logger logger = Logger.getLogger(HandshakeResponse.class.getName());

    /**
     * Constructor to invoke message handlers
     *
     * @param handRecord Handshake record
     * @param trace Holds the trace object
     * @param workflow Handshake workflow
     */
    public HandshakeResponse(AHandshakeRecord handRecord,
            MessageTrace trace, TLS10HandshakeWorkflow workflow) {
        if (handRecord instanceof ServerHello) {
            logger.debug("Server Hello message received");
            serverHello = new ServerHelloHandler();
            serverHello.handleResponse(handRecord);
            workflow.switchToState(trace, EStates.SERVER_HELLO);
            trace.setCurrentRecord((ServerHello) handRecord);
        }
        if (handRecord instanceof Certificate) {
            logger.debug("Cerificate message received");
            certificate = new CertificateHandler();
            certificate.handleResponse(handRecord);
            workflow.switchToState(trace, EStates.SERVER_CERTIFICATE);
            trace.setCurrentRecord((Certificate) handRecord);
        }
        if (handRecord instanceof ServerKeyExchange) {
            logger.debug("Server Key Exchange message received");
            serverKeyExchange = new ServerKeyExchangeHandler();
            serverKeyExchange.handleResponse(handRecord);
            workflow.switchToState(trace, EStates.SERVER_KEY_EXCHANGE);
            trace.setCurrentRecord((ServerKeyExchange) handRecord);
        }
        if (handRecord instanceof ServerHelloDone) {
            logger.debug("Server Hello Done message received");
            workflow.switchToState(trace, EStates.SERVER_HELLO_DONE);
            trace.setCurrentRecord((ServerHelloDone) handRecord);
        }
    }
}
