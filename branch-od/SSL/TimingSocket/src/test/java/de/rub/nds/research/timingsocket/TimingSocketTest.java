package de.rub.nds.research.timingsocket;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 */
public class TimingSocketTest {
    
    @BeforeClass
    public void setUp() {
        // code that will be invoked before this test starts
    }
    
    @Test
    public void aTest() {
        System.out.println("Test");
    }
    
    @AfterClass
    public void cleanUp() {
        // code that will be invoked after this test ends
    }
}
