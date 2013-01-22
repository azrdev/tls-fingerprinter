package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.List;

/**
 * Test/Attack results.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 18, 2013
 */
public class ResultWrapper {

    private AParameters parameters;
    private List<MessageContainer> traceList;
    private Class<IFingerprinter> analyzer;

    public ResultWrapper(final AParameters parameters,
            final List<MessageContainer> traceList,
            final Class<IFingerprinter> analyzer) {
        this.parameters = parameters;
        this.traceList = traceList;
        this.analyzer = analyzer;
    }

    public AParameters getParameters() {
        return this.parameters;
    }

    public List<MessageContainer> getTraceList() {
        return this.traceList;
    }
    
    public Class<IFingerprinter> getAnalyzer() {
        return this.analyzer;
    }
}
