package de.rub.nds.ssl.stack.workflows.commons;

/**
 * Marker interface to signal workflow states.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Apr 11, 2012
 */
public interface IWorkflowState {

    /**
     * Get the ID of this state.
     *
     * @return ID of the associated state.
     */
    int getID();
}
