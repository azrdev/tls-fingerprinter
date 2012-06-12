package de.rub.nds.research.ssl.stack;

import java.math.BigInteger;
import java.util.List;

/**
 * Helper routines for common use
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
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
    public static String bytesToHex(final byte[] bytes) {
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

//    public static String bytesToHex(byte[] array) {
//        StringBuilder sb = new StringBuilder(200);
//        int bytecon = 0;
//        for (int i = 0; i < array.length; i++) {
//            bytecon = array[i] & 0xFF;
//
//            // byte-wise AND converts signed byte to unsigned.
//            if (bytecon < 16) {
//                sb.append("0x0" + Integer.toHexString(bytecon).toUpperCase() + ", ");
//            } // pad on left if single hex digit.
//            else {
//                sb.append("0x" + Integer.toHexString(bytecon).toUpperCase() + ", ");
//            }
//            // pad on left if single hex digit.
//        }
//        return sb.toString();
//    }
    
    /**
     * Computes the Greatest Common Divisor of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Greatest Common Divisor of both integers
     */
    public static int findGCD(int a, int b) {
        if (b == 0) {
            return a;
        }
        return findGCD(b, a % b);
    }

    /**
     * Computes the Greatest Common Divisor of two BigIntegers.
     *
     * @param a First BigInteger
     * @param b Second BigInteger
     * @return Greatest Common Divisor of both BigIntegers
     */
    public static BigInteger findGCD(BigInteger a, BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) == 0) {
            return a;
        }
        return findGCD(b, a.mod(b));
    }

    /**
     * Computes the Least Common Multiple of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Least Common Multiple of both integers
     */
    public static int findLCM(int a, int b) {
        int result = 0;
        int num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = i * num1;
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of two BigIntegers.
     *
     * @param ba First BigInteger
     * @param bb Second BigInteger
     * @return Least Common Multiple of both BigIntegers
     */
    public static BigInteger findLCM(BigInteger ba, BigInteger bb) {
        BigInteger result = BigInteger.ZERO;
        long a = ba.longValue();
        long b = bb.longValue();
        long num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = BigInteger.valueOf(i * num1);
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of a list of BigIntegers.
     *
     * @param numbers List of BigIntegers
     * @return Least Common Multiple of all BigIntegers contained in the list
     */
    public static BigInteger findLCM(List<BigInteger> numbers) {
        BigInteger result = numbers.get(0);
        for (int i = 1; i < numbers.size(); i++) {
            result = findLCM(result, numbers.get(i));
        }
        return result;
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     *
     * @param array Array which size should be corrected
     * @param blockSize Blocksize - the resulting array length will be a
     * multiple of it
     * @param removeSignByte If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    public static byte[] correctSize(final byte[] array, int blockSize,
            boolean removeSignByte) {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && remainder > 0 && result[0] == 0x0) {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder,
                    result.length);
            result = tmp;
        }

        return result;
    }
}
