package de.rub.nds.ssl.stack.tests.workflows;

import de.rub.nds.ssl.stack.tests.trace.MessageTrace;
import java.util.Observer;

/**
 * Interface to signal a workflow based object.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Apr 11, 2012
 */
public abstract class AWorkflow {

    /**
     * Current state identifier.
     */
    private int currentState = 0;
    /**
     * Observable bridges for each state.
     */
    private ObservableBridge[] states;

    /**
     * Public constructor for a workflow. Assigns an observable bridge to each
     * state for observation reasons.
     *
     * @param workflowStates States of this workflow
     */
    public AWorkflow(final WorkflowState[] workflowStates) {
        if (workflowStates != null) {
            states = new ObservableBridge[workflowStates.length];
            for (int i = workflowStates.length - 1; i >= 0; i--) {
                states[i] = new ObservableBridge(workflowStates[i]);
            }
        }
    }

    /**
     * Start the workflow.
     */
    public abstract void start();

    /**
     * Add an observer for a specific workflow state.
     *
     * @param observer Observer to be registered
     * @param state State for which to register
     */
    public void addObserver(final Observer observer, final WorkflowState state) {
        states[state.getID()].addObserver(observer);
    }

    /**
     * Delete an observer for a specific workflow state.
     *
     * @param observer Observer to be unregistered
     * @param state State for which to unregister
     */
    public void deleteObserver(final Observer observer,
            final WorkflowState state) {
        states[state.getID()].deleteObserver(observer);
    }

    /**
     * Delete all observers for a specific workflow state.
     *
     * @param state State for which to unregister
     */
    public void deleteObservers(final WorkflowState state) {
        states[state.getID()].deleteObservers();
    }

    /**
     * Counts observers registered for a specific state.
     *
     * @param state State for which to count
     * @return Number of observers for this specific state
     */
    public int countObservers(final WorkflowState state) {
        return states[state.getID()].countObservers();
    }

    /**
     * Tests if the changed flag of this state is set.
     *
     * @param state State to test for changes
     * @return True if the changed flag if set for this state.
     */
    public boolean hasChanged(final WorkflowState state) {
        return states[state.getID()].hasChanged();
    }

    /**
     * Notify changes to the the observers and deliver the trace object.
     *
     * @param trace Message trace
     * @param state State for which this notification is valid
     */
    public void notifyObservers(final MessageTrace trace, final WorkflowState state) {
        states[state.getID()].notifyObservers(trace);
    }

    /**
     * Notify changes to the the observers of the current state and deliver the
     * trace object.
     *
     * @param trace Message trace
     */
    public void notifyCurrentObservers(final MessageTrace trace) {
        states[currentState].notifyObservers(trace);
    }

    /**
     * Switches to the next state. If the last state is reached the workflow
     * will remain in this last state. A call will automatically set the changed
     * flag of the returned state.
     *
     * @return New current state
     */
    public WorkflowState nextState() {
        this.currentState++;

        // sanity check
        if (this.currentState > this.states.length) {
            this.currentState = this.states.length - 1;
        }


        ObservableBridge newState = this.states[this.currentState];
        newState.setChangedFlag();

        return newState.getState();
    }

    /**
     * Switches to the previous state. If the first state is reached the
     * workflow will remain in this first state. A call will automatically set
     * the changed flag of the returned state.
     *
     * @return New current state
     */
    public WorkflowState previousState() {
        this.currentState--;

        // sanity check
        if (this.currentState < 0) {
            this.currentState = 0;
        }

        ObservableBridge newState = this.states[this.currentState];
        newState.setChangedFlag();

        return newState.getState();
    }

    /**
     * Get the current state in the handshake.
     *
     * @return Current handshake state
     */
    public int getCurrentState() {
        return this.currentState;
    }

    /**
     * Set the current state in the handshake.
     *
     * @param state Current handshake state
     */
    public void setCurrentState(int state) {
        this.currentState = state;
        ObservableBridge newState = this.states[this.currentState];
        newState.setChangedFlag();
    }

    /**
     * Resets the internal state machine to its initial state.
     */
    protected void resetState() {
        this.currentState = 0;
    }
}
