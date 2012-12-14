package de.rub.nds.ssl.stack.tests.fingerprint;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.BeforeClass;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.tests.parameters.HeaderParameters;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;

public abstract class GenericFingerprintTest {
    /**
     * Help utilities for testing.
     */
    protected MessageUtils utils = new MessageUtils();

    /**
     * Handshake workflow to observe.
     */
    protected TLS10HandshakeWorkflow workflow;
    /**
     * Test host.
     */
    protected String HOST = "localhost";
    /**
     * Test port.
     */
    protected int PORT = 443;
    /**
     * Default protocol version.
     */
    protected EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /**
     * Test parameters.
     */
    protected HeaderParameters parameters = new HeaderParameters();
    /**
     * Log4j logger initialization.
     */
    protected Logger logger = Logger.getRootLogger();
    /**
     * Test counter.
     */
    protected int counter = 1;


    /**
     * Load the logging properties.
     */
    @BeforeClass
    public void setUp() {
        PropertyConfigurator.configure("logging.properties");
    }


}
