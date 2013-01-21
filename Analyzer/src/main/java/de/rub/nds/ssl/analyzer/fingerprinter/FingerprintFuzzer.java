package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.db.FillBehaviourDB;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Fingerprint fuzzer to create a database of fingerprints
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jan 10, 2012
 */
public class FingerprintFuzzer implements IFingerprinter {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Test implementation
     */
    public ETLSImplementation impl;
    /**
     * Fingerprint testcase
     */
    public String testcase;
    /**
     * Tested handshake state
     */
    public EStates state;
    /**
     * Test parameters
     */
    public AParameters parameters;

    /**
     * Initialize the fuzzer
     *
     * @param testcase 
     * @param parameters Test parameters
     * @param impl Test implementation
     * @param state  
     */
    public FingerprintFuzzer(String testcase, ETLSImplementation impl,
            EStates state,
            AParameters parameters) {
        this.testcase = testcase;
        this.impl = impl;
        this.state = state;
        this.parameters = parameters;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(List<MessageContainer> traceList) {
        FillBehaviourDB behaviour = new FillBehaviourDB();
        try {
            behaviour.insertFingerprint(parameters, traceList, 
                    this.state.name(), this.testcase, this.impl.name());
        } catch (Exception e) {
            logger.error("Unspecified Error.", e);
        }

    }


    @Override
    public void init(AParameters parameters) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
