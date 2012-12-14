package de.rub.nds.ssl.analyzer.common;

import org.testng.annotations.BeforeSuite;

/**
 * Load the properties for the test suite.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 01, 2012
 */
public class TestSuiteInit {

    /**
     * Method is called before the suite tests are executed. Setup of the suite
     * is performed loading the test properties.
     */
    @BeforeSuite
    public void setUpSuite() {
        TestConfiguration.getInstance();
    }
}
