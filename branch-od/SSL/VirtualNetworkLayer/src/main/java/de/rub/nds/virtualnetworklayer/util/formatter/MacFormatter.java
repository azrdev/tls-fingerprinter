package de.rub.nds.virtualnetworklayer.util.formatter;

import java.util.List;

/**
 * Formatter for Mac addresses.
 * </p>
 * exemplary output: {@code 00:80:41:ae:fd:7e}
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class MacFormatter extends StringFormatter {

    public static String toString(byte[] data) {
        StringBuilder builder = new StringBuilder(18);

        for (byte b : data) {
            if (builder.length() > 0) {
                builder.append(':');
            }

            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }

    public static String toString(List<byte[]> addresses) {
        StringBuilder builder = new StringBuilder(addresses.size() * 6);
        builder.append("[");

        for (byte[] address : addresses) {
            if (builder.length() != 1) {
                builder.append(", ");
            }
            builder.append(toString(address));
        }

        builder.append("]");

        return builder.toString();
    }

}
