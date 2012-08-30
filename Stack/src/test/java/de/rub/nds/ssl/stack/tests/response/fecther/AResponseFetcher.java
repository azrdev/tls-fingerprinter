package de.rub.nds.ssl.stack.tests.response.fecther;

import de.rub.nds.ssl.stack.tests.workflows.AWorkflow;
import java.util.Observable;

/**
 * Abstarct ResponseFetcher protoype.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Aug 30, 2012
 */
public abstract class AResponseFetcher extends Observable implements Runnable {
    /**
     * Handshake workflow.
     */
    protected AWorkflow workflow;
    
    public AResponseFetcher(AWorkflow workflow) {
        this.workflow = workflow;
        //add the workflow as observer
        this.addObserver(this.workflow);
    }

}
