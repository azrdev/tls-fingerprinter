package de.rub.nds.ssl.stack.workflows.commons;

import java.util.Observable;

/**
 * Bridge to render objects observable.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Apr 11, 2012
 */
public final class ObservableBridge extends Observable {
    /**
     * Associated state of this bridge.
     */
    private IWorkflowState state;

    /**
     * Creates a new bridge and associates it with the handled state.
     *
     * @param handeledState State to be associated with this bridge.
     */
    public ObservableBridge(final IWorkflowState handeledState) {
        this.state = handeledState;
    }

    /**
     * Get the associated state.
     *
     * @return State associated with this bridge.
     */
    public IWorkflowState getState() {
        return this.state;
    }

    /**
     * Set the changed flag.
     */
    public void setChangedFlag() {
        setChanged();
    }
}
