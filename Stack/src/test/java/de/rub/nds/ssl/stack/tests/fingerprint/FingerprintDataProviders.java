package de.rub.nds.research.ssl.stack.tests.fingerprint;

import org.testng.annotations.DataProvider;

/**
 * Data providers with parameters passed to the fingerprinting
 * tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 21, 2012
 */
public class FingerprintDataProviders {
	

	/**
	 * Record Header parameters.
	 * @return Array of parameters.
	 */
	@DataProvider(name = "recordHeader")
    public static Object[][] createRecordHeaderData() {
        return new Object[][]{
        		 {"Wrong message type", new byte[]{(byte)0x17},
        			 null, null},
            	 {"Invalid protocol version 0xff,0xff",
            		 null, new byte[]{(byte)0xff,(byte)0xff},null},
                 {"Invalid length 0x00,0x00",
                   null, null, new byte[]{(byte)0x00,(byte)0x00}},
                 {"Invalid length 0xff,0xff",
            	   null, null, new byte[]{(byte)0xff,(byte)0xff}},
        };
    }
	
	/**
	 * Handshake header parameters.
	 * @return Array of parameters
	 */
	@DataProvider(name = "handshakeHeader")
    public static Object[][] createHandshakeHeaderData() {
        return new Object[][]{
                    {"Wrong message type", new byte[]{(byte) 0xff},
                        null},
                    {"Invalid length 0x00,0x00,0x00",
                        null, new byte[]{(byte) 0x00, (byte) 0x00,
                            (byte) 0x00}},
                    {"Invalid length 0xff,0xff,0xff",
                        null, new byte[]{(byte) 0xff, (byte) 0xff,
                            (byte) 0xff}},
          };
    }

}
