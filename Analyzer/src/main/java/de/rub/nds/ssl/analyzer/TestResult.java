package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.ArrayList;
import java.util.List;

/**
 * Test/Attack results.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 18, 2013
 */
public class TestResult {

    /**
     * Handshake/Message parameters.
     */
    private AParameters parameters;
    /**
     * Complete tracelist of the handshake.
     */
    private List<MessageContainer> traceList;
    /**
     * Configured analyzer for this result.
     */
    private Class<IFingerprinter> analyzer;
    /**
     * Testcase name.
     */
    private String testName;

    /**
     * Public constructor for the result wrapper.
     *
     * @param parameters Handshake/Message parameters
     * @param traceList Trace list of the handshake
     * @param analyzer Configured analyzer
     */
    public TestResult(final AParameters parameters,
            final List<MessageContainer> traceList,
            final Class<IFingerprinter> analyzer) {
        // deep copy
        try {
            this.parameters = parameters.clone();
        } catch (CloneNotSupportedException e) {
            // this should never happen!
            throw new RuntimeException(e);
        }
        this.traceList = new ArrayList<MessageContainer>(traceList);
        try {
            this.analyzer = (Class<IFingerprinter>) Class.forName(analyzer.
                    getCanonicalName());
        } catch (ClassNotFoundException e) {
            // this should never happen!
            throw new RuntimeException(e);
        }
    }

    /**
     * Getter for parameters.
     * @return Handshake/Message parameters
     */
    public AParameters getParameters() {
        return this.parameters;
    }

    /**
     * Getter for the trace list.
     * @return Complete trace list of the handshake
     */
    public List<MessageContainer> getTraceList() {
        return this.traceList;
    }

    /**
     * Getter for the analyzer.
     * @return Configured analyzer for these results.
     */
    public Class<IFingerprinter> getAnalyzer() {
        return this.analyzer;
    }

    /**
     * Getter for the test case name.
     * @return Name of the test case
     */
    public String getTestName() {
        return testName;
    }

    /**
     * Setter for parameters.
     * @param parameters tHandshake/Message parameters
     */
    public void setParameters(final AParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Setter for the trace list.
     * @param traceList Complete trace list of the handshake
     */
    public void setTraceList(final List<MessageContainer> traceList) {
        this.traceList = traceList;
    }

    /**
     * Setter for the analyzer.
     * @param analyzer Configured analyzer for these results.
     */
    public void setAnalyzer(final Class<IFingerprinter> analyzer) {
        this.analyzer = analyzer;
    }

    /**
     * Setter for the test case name.
     * @param testName Name of the test case
     */
    public void setTestName(final String testName) {
        this.testName = testName;
    }
}
