package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.db.FillBehaviourDB;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
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
     * Test parameters.
     */
    private AParameters parameters;

    /**
     * Public constructor without any initialization.
     * Be sure to set all values before calling analyze()!
     */
    public FingerprintFuzzer() {
        
    }
    
    /**
     * Public constructor for FingerprintFuzzer.
     * Triggers init(AParameters parameters).
     * 
     * @param testcase Name of the Testcase
     * @param implementation SSL/TLS of target
     * @param parameters Used parameters
     */
    public FingerprintFuzzer(final String testcase,
            final ETLSImplementation implementation,
            final AParameters parameters) {
        setTestcase(testcase);
        setImplementation(implementation);
        init(parameters);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<MessageContainer> traceList) {
        FillBehaviourDB behaviour = new FillBehaviourDB();
        try {
            behaviour.insertFingerprint(parameters, traceList, this.testcase,
                    this.implementation.name());
        } catch (Exception e) {
            logger.error("Unspecified Error.", e);
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(final AParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Setter for the test case name.
     * @param testcase Test case name.
     */
    public void setTestcase(final String testcase) {
        this.testcase = testcase;
    }

    /**
     * Setter for implementation.
     * @param impl Implementation
     */
    public void setImplementation(final ETLSImplementation impl) {
        this.implementation = impl;
    }
}
