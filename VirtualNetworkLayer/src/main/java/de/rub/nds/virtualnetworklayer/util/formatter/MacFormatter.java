package de.rub.nds.virtualnetworklayer.util.formatter;

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

}
