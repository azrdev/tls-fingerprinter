
/*
 * Copyright 2011 Sec2 Consortium
 * 
 * This source code is part of the "Sec2" project and as this remains property
 * of the project partners. Content and concepts have to be treated as
 * CONFIDENTIAL. Publication or partly disclosure without explicit written
 * permission is prohibited.
 * For details on "Sec2" and its contributors visit
 * 
 *        http://www.sec2.org
 */
package de.rub.nds.research.ssl.stack.tests.workflows;

import java.util.Observable;

/**
 * Bridge to render objects observable.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Apr 11, 2012
 */
public class ObservableBridge extends Observable {
    /**
     * Associated state of this bridge.
     */
    private WorkflowState state;
    
    /**
     * Creates a new bridge and associates it with the handled state.
     * @param handeledState State to be associated with this bridge.
     */
    public ObservableBridge(WorkflowState handeledState) {
        this.state = handeledState;
    }
    
    /**
     * Getter for the associated state.
     * @return State associated with this bridge.
     */
    public WorkflowState getState() {
        return this.state;
    }
    
    /**
     * Setter for the changed flag.
     */
    public void setChangedFlag() {
        setChanged();
    }
}
