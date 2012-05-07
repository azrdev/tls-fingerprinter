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
