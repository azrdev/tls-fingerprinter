package de.rub.nds.ssl.stack;

import java.lang.IllegalArgumentException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.rub.nds.ssl.stack.Utility.bytesIdToHex;

/**
 * Helper routines for common use
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 *
 * Feb 05, 2014
 */
public final class Utility {

    /**
     * Bits in byte.
     */
    public static final int BITS_IN_BYTE = 8;
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
    private Utility() {}

    /**
     * convert a hex string representation to the corresponding byte array.
     *
     * @throws IllegalArgumentException if the number of hex digits was uneven or hex
     *      contained non-hex chars.
     */
    public static byte[] hexToBytes(final String hex)
            throws IllegalArgumentException {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int msb = Character.digit(hex.charAt(i), 16);
            int lsb = Character.digit(hex.charAt(i+1), 16);
            if(msb < 0 || lsb < 0) {
                throw new IllegalArgumentException("Illegal character in " +
                        hex.substring(i, i + 2));
            }
            data[i / 2] = (byte) ((msb << 4) + lsb);
        }
        return data;
    }

	/**
	 * Convert an identifier stored in a byte array to its hex and integer representation.
	 * @param bytes
	 * @return string
	 */
	public static String bytesIdToHex(final byte[] bytes) {
		return String.format("0x%s (%d)",
				bytesToHex(bytes, false), bytesToInt(bytes));
	}

	public static String bytesIdToHex(final byte b) {
		return bytesIdToHex(new byte[]{b});
	}

    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes) {
	    return bytesToHex(bytes, true);
    }

    /**
     *
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @param addSpaces insert a space char after each 2 hex characters
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes, boolean addSpaces) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
	        if(addSpaces)
                builder.append(' ');
        }

        return builder.toString().trim();
    }
    
    public static String bytesToHex(final byte bytes){
        return bytesToHex(new byte[]{bytes});
    }

    public static String bytesToHex(final byte bytes, boolean addSpaces){
        return bytesToHex(new byte[]{bytes}, addSpaces);
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
     * Converts a byte[] to int.
     *
     * @param bytes 4 bytes array to be converted
     * @return Integer representation of the byte[]
     */
    public static int bytesToInt(final byte... bytes) {
        byte[] copy = bytes;
        if(copy.length < 4){
            byte[] tmp = new byte[4];
            System.arraycopy(bytes, 0, tmp, tmp.length-copy.length, copy.length);
            copy = tmp;
        }
        return (int) ((0xFF & copy[0]) << Utility.BITS_IN_BYTE * 3
                | (0xFF & copy[1]) << Utility.BITS_IN_BYTE * 2
                | (0xFF & copy[2]) << Utility.BITS_IN_BYTE
                | (0xFF & copy[3]));
    }

    /**
     * Converts an int value to byte[].
     *
     * @param toConvert Value to converted.
     * @return Byte array representation of the integer.
     */
    public static byte[] intToBytes(final int toConvert) {
        byte[] result = new byte[4];
        result[0] = (byte) ((toConvert >> Utility.BITS_IN_BYTE * 3) & 0xff);
        result[1] = (byte) ((toConvert >> Utility.BITS_IN_BYTE * 2) & 0xff);
        result[2] = (byte) ((toConvert >> Utility.BITS_IN_BYTE) & 0xff);
        result[3] = (byte) ((toConvert) & 0xff);

        return result;
    }
    
    /**
     * Converts a short value to byte[].
     *
     * @param toConvert Value to converted.
     * @return Byte array representation of the short.
     */
    public static byte[] shortToBytes(final short toConvert) {
        byte[] result = new byte[2];
        result[0] = (byte) (toConvert & 0xff);
        result[1] = (byte) ((toConvert >> Utility.BITS_IN_BYTE) & 0xff);

        return result;
    }
    
    /**
     * Converts a byte[] to short.
     *
     * @param toConvert Value to converted.
     * @return Short representation of the byte array.
     */
    public static short bytesToShort(final byte[] toConvert) {
        short result = toConvert[0];
        result += (toConvert[1] >> Utility.BITS_IN_BYTE);

        return result;
    }

    /**
     * Copies an array and converts it to List
     */
    public static <T> List<T> deepCopyAsList(T[] array) {
        return Arrays.asList(Arrays.copyOf(array, array.length));
    }
}
