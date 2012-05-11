package de.rub.nds.research.ssl.stack.tests.workflows;

/**
 * Marker interface to signal workflow states
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * Apr 11, 2012
 */
public interface WorkflowState {
    /**
     * Getter for enum ID.
     * @return ID of the associated state.
     */
    int getID();
}
