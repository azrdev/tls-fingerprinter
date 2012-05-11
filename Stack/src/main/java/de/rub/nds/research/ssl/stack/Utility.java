package de.rub.nds.research.ssl.stack;

/**
 * Helper routines for common use
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 20, 2011
 */
public abstract class Utility {

    /**
     * Valid Hex Chars.
     */
    private final static char[] HEXCHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Private constructor - Utility class only.
     */
    private Utility() {
    }

    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String byteToHex(final byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
            builder.append(' ');
        }

        return builder.toString();
    }
}
