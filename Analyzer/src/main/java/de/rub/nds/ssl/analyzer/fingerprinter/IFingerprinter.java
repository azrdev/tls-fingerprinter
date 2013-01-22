package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.List;

/**
 * Fingerprint analysis of a Unit Test.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de May 26, 2012
 */
public interface IFingerprinter {

    /**
     * Match a fingerprint using the test trace.
     *
     * @param traceList MessageContainer list of a testrun
     */
    void analyze(final List<MessageContainer> traceList);

    /**
     * (Re-)Initialize analyzer.
     *
     * @param parameters Test parameters
     */
    void init(final AParameters parameters);
}
