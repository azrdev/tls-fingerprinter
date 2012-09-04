package de.rub.nds.ssl.stack.tests.response.fecther;

import de.rub.nds.ssl.stack.tests.workflows.AWorkflow;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
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
    /**
     * Socket.
     */
    protected Socket socket;
    /**
     * Signalizes if further bytes should be fetched.
     */
    private boolean fetchBytes = true;
    
    /**
     * Initialize the fetcher.
     *
     * @param so Socket to work with
     * @param workflow Workflow to notify
     */
    public AResponseFetcher(final Socket so, final AWorkflow workflow) {
        this.workflow = workflow;
        //add the workflow as observer
        this.addObserver(this.workflow);
        
        if (so != null) {
            this.socket = so;
        }
    }
    
    /**
     * Checks if fetching bytes should be continued.
     */
    public boolean continueFetching() {
        return this.fetchBytes;
    }
    
    /**
     * Stop fetching bytes from the Socket. Will terminate the thread!
     */
    public void stopFetching() {
        this.fetchBytes = false;
    }
}
