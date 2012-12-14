package de.rub.nds.ssl.analyzer.tests;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Dummy Test - does nothing.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 14, 2012
 */
public class Dummy {
    
    @BeforeClass
    public void setUp() {
        // code that will be invoked before this test starts
    }
    
    @Test(enabled = true)
    public void aTest() {
        System.out.println("Test");
    }
    
    @AfterClass
    public void cleanUp() {
        // code that will be invoked after this test ends
    }
}
