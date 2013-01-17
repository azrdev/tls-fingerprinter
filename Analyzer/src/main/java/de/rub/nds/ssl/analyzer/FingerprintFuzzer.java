package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.analyzer.common.ETLSImplementation;
import de.rub.nds.ssl.analyzer.db.FillBehaviourDB;
import de.rub.nds.ssl.analyzer.tests.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.ArrayList;

/**
 * Fingerprint fuzzer to create a database of fingerprints
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jan 10, 2012
 */
public class FingerprintFuzzer extends AFingerprintAnalyzer {

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
     * @param parameters Test parameters
     * @param impl Test implementation
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
    public void analyze(ArrayList<MessageContainer> traceList) {
        FillBehaviourDB behaviour = new FillBehaviourDB();
        try {
            behaviour.insertFingerprint(parameters, traceList, 
                    this.state.name(), this.testcase, this.impl.name());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
