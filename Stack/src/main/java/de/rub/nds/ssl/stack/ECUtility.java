package de.rub.nds.ssl.stack;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import java.util.Arrays;

/**
 * Helpful routines when working with elliptic curves.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Aug 12, 2013
 */
public final class ECUtility {

    /**
     * Utility class only.
     */
    private ECUtility() {
    }

    /**
     * Remove leading zeros from arrays - if any!
     *
     * @param array Array to be stripped.
     * @return Array with leading zeros stripped off.
     */
    private static final byte[] stripLeadingZeroBytes(byte[] array) {
        int counter = 0;
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0x00) {
                break;
            }
            counter++;
        }
        
        return Arrays.copyOfRange(array, counter, array.length);
    }

    /**
     * Encode an EC Point according to X9.62.
     *
     * @param xBytes X coordinate
     * @param yBytes Y coordinate
     * @param pointFormat Desired point encoding
     * @return Encoded point
     */
    public static byte[] encodeX9_62(final byte[] xBytes, final byte[] yBytes,
            final EECPointFormat pointFormat) {
        byte[] result;
        // sanitze input
        byte[] x = stripLeadingZeroBytes(xBytes);
        byte[] y = stripLeadingZeroBytes(yBytes);

        // pad to equal lengths
        int newLength = Math.max(x.length, y.length);
        x = prependZeros(newLength, x);
        y = prependZeros(newLength, y);
        
        switch (pointFormat) {
            case ANSI_X962_COMPRESSED_CHAR2:
                // strip of Y coordinate
                result = new byte[x.length + 1];
                if ((y[0] & (0x01)) == 1) {
                    result[0] = 0x03;
                } else {
                    result[0] = 0x02;
                }
                System.arraycopy(x, 0, result, 1, x.length);
                // TODO check this code for correctness in this case
                break;
            case ANSI_X962_COMPRESSED_PRIME:
                // strip of Y coordinate
                result = new byte[x.length + 1];
                if ((y[0] & (0x01)) == 1) {
                    result[0] = 0x03;
                } else {
                    result[0] = 0x02;
                }
                System.arraycopy(x, 0, result, 1, x.length);
                break;
            case UNCOMPRESSED:
                result = new byte[x.length + y.length + 1];
                result[0] = 0x04;
                System.arraycopy(x, 0, result, 1, x.length);
                System.arraycopy(y, 0, result, 1 + x.length, y.length);
                break;
            default:
                result = new byte[0];
                break;
        }

        return result;
    }
    
    private static byte[] prependZeros(final int newLength, final byte[] bytes) {
        byte[] result = new byte[newLength];
        System.arraycopy(bytes, 0, result, newLength - bytes.length, bytes.length);
        
        return result;
    }
}
