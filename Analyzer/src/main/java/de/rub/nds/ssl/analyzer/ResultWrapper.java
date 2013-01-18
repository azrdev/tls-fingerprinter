package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.List;

/**
 * Test/Attack results.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 18, 2013
 */
public class ResultWrapper {

    private AParameters parameters;
    private List<MessageContainer> traceList; 
    
    public ResultWrapper(final AParameters parameters, final List<MessageContainer> traceList) {
        this.parameters = parameters;
        this.traceList = traceList;
    }
    
    public AParameters getParameters() {
        return this.parameters;
    }
    
    public List<MessageContainer> getTraceList() {
        return this.traceList;
    }
}
