package de.rub.nds.ssl.stack;

/**
 * Helper routines for common use
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 *
 * Dec 20, 2011
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
    
    public static String bytesToHex(final byte bytes){
        return bytesToHex(new byte[]{bytes});
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
        return (int) ((0xFF & bytes[0]) << Utility.BITS_IN_BYTE * 3
                | (0xFF & bytes[1]) << Utility.BITS_IN_BYTE * 2
                | (0xFF & bytes[2]) << Utility.BITS_IN_BYTE
                | (0xFF & bytes[3]));
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
        result[1] = (byte) ((toConvert >> 8) & 0xff);

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
        result += (toConvert[1] >> 8);

        return result;
    }
}
