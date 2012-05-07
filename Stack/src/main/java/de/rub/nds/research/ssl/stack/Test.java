package de.rub.nds.research.ssl.stack;

import java.io.IOException;

/**
 * <DESCRIPTION>
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * 
 * Nov 11, 2011
 */
public class Test {
    public static void main(String args[]) throws IOException {
        TLSPecker myPecker = new TLSPecker("/home/chris/Desktop/test");
        myPecker.checkTLSSupport("www.rub.de", 443);
    }
}
