package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.AAnalyzerComponent;
import de.rub.nds.ssl.analyzer.parameters.HeaderParameters;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
import org.apache.log4j.Logger;

public abstract class AGenericFingerprintTest extends AAnalyzerComponent {

    /**
     * Help utilities for testing.
     */
    protected MessageUtils utils = new MessageUtils();
    /**
     * Handshake workflow to observe.
     */
    protected TLS10HandshakeWorkflow workflow;
    /**
     * Default protocol version.
     */
    protected EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test headerParameters.
     */
    protected HeaderParameters headerParameters = new HeaderParameters();
    /**
     * Log4j logger initialization.
     */
    protected Logger logger = Logger.getRootLogger();
    /**
     * Test counter.
     */
    protected int counter = 1;

    /**
     * Print the test banner.
     */
    protected final void printBanner() {
        logger.info("########################################################");
        logger.info(this.getClass().getCanonicalName());
        logger.info("########################################################");
    }
}
