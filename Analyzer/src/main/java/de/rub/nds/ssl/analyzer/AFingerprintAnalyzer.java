package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.ArrayList;

/**
 * Fingerprint analysis of a Unit Test.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de May 26, 2012
 */
public abstract class AFingerprintAnalyzer {

    /**
     * Match a fingerprint using the test trace.
     *
     * @param traceList MessageContainer list of a testrun
     */
    public abstract void analyze(ArrayList<MessageContainer> traceList);
}
