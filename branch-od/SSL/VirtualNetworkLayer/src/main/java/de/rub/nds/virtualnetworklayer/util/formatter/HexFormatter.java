package de.rub.nds.virtualnetworklayer.util.formatter;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class HexFormatter extends StringFormatter {

    public static String toString(byte[] buffer) {
        return toHexDump(buffer, 0, buffer.length);
    }

    public static String toHexDump(byte[] data, int offset, int length) {
        StringBuilder builder = new StringBuilder();

        for (int i = offset; i < length; i++) {
            builder.append(Integer.toHexString(data[i] & 0xFF)).append(" ");

            if ((i - offset) % 16 == 15) {
                builder.append('\n');
            }
        }

        return builder.toString();
    }
}
