package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.db.FillBehaviourDB;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Fingerprint fuzzer to create a database of fingerprints.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jan 10, 2012
 */
public final class FingerprintFuzzer implements IFingerprinter {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Test implementation.
     */
    private ETLSImplementation implementation;
    /**
     * Fingerprint testcase.
     */
    private String testcase;
    /**
     * Tested handshake state.
     */
    private EStates state;
    /**
     * Test parameters.
     */
    private AParameters parameters;

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<MessageContainer> traceList) {
        FillBehaviourDB behaviour = new FillBehaviourDB();
        try {
            behaviour.insertFingerprint(parameters, traceList,
                    this.state.name(), this.testcase, this.implementation.name());
        } catch (Exception e) {
            logger.error("Unspecified Error.", e);
        }

    }

    @Override
    public void init(final AParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * @param testcase the testcase to set
     */
    public void setTestcase(String testcase) {
        this.testcase = testcase;
    }

    /**
     * @param state the state to set
     */
    public void setState(EStates state) {
        this.state = state;
    }

    /**
     * @param impl the impl to set
     */
    public void setImplementation(ETLSImplementation impl) {
        this.implementation = impl;
    }
    
}
