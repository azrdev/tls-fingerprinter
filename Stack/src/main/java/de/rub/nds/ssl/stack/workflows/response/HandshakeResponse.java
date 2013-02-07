package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHelloDone;
import de.rub.nds.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import org.apache.log4j.Logger;

/**
 * Determine the handshake record in response and invoke the appropriate
 * handler.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 15, 2012
 */
public final class HandshakeResponse {

    /**
     * Log4J logger.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Private constructor - Utility class only.
     */
    private HandshakeResponse() {
    }

    /**
     * Invoke message handlers.
     *
     * @param handRecord Handshake record
     * @param trace Holds the trace object
     * @param workflow Handshake workflow
     */
    public static void invokeMessageHandlers(
            final AHandshakeRecord handRecord,
            final MessageContainer trace,
            final TLS10HandshakeWorkflow workflow) {
        IHandshakeStates state;

        if (handRecord instanceof ServerHello) {
            logger.debug("Server Hello message received");
            state = new ServerHelloHandler();
            state.handleResponse(handRecord);
            workflow.switchToState(trace, EStates.SERVER_HELLO);
            trace.setCurrentRecord((ServerHello) handRecord);
        }
        if (handRecord instanceof Certificate) {
            logger.debug("Cerificate message received");
            state = new CertificateHandler();
            state.handleResponse(handRecord);
            workflow.switchToState(trace, EStates.SERVER_CERTIFICATE);
            trace.setCurrentRecord((Certificate) handRecord);
        }
        if (handRecord instanceof ServerKeyExchange) {
            logger.debug("Server Key Exchange message received");
            state = new ServerKeyExchangeHandler();
            state.handleResponse(handRecord);
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
