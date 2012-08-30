package de.rub.nds.ssl.stack.tests.fingerprint;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.testng.annotations.BeforeClass;

import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.HeaderParameters;
import de.rub.nds.ssl.stack.tests.common.SSLTestUtils;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow;

public abstract class GenericFingerprintTest {
    /**
     * Help utilities for testing.
     */
    protected SSLTestUtils utils = new SSLTestUtils();

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
