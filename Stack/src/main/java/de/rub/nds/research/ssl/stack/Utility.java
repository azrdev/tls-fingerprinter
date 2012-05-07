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
package de.rub.nds.research.ssl.stack;

/**
 * Helper routines for common use
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 20, 2011
 */
final public class Utility {
    
    /**
     * Converts a byte array into its hex string representation.
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
     public static String byteToHex(final byte[] bytes) {
        final char[] HEX_CHARS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEX_CHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEX_CHARS[bytes[i] & 0xf]);
            builder.append(' ');
        }
        
        return builder.toString();
    }
}
