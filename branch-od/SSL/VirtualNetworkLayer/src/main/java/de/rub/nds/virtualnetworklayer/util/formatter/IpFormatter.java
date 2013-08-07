package de.rub.nds.virtualnetworklayer.util.formatter;

/**
 * Formatter for Ip addresses.
 * </p>
 * exemplary output Ip Version 4: {@code 127.0.0.1}
 * </p>
 * exemplary output Ip Version 6: {@code fe80::116b:9d3d:4d13:5273}</br>
 * Ip Version 6 addresses are compressed: replacing an sequence
 * of empty octets with a colon (:).
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class IpFormatter extends StringFormatter {

    public static String toString(byte[] data) {
        if (data == null) {
            return "0.0.0.0";
        }

        if (data.length == 4) {
            return toIp4String(data);
        }

        return toIp6String(data);
    }

    public static String toIp4String(byte[] data) {
        StringBuilder builder = new StringBuilder(16);

        for (int i = 0; i < 4; i++) {
            builder.append(data[i] & 0xFF);
            if (i < 3) {
                builder.append('.');
            }
        }

        return builder.toString();
    }

    public static String toIp6String(byte[] data) {
        StringBuilder builder = new StringBuilder(32);

        int compressedParts = 0;
        for (int i = 0; i < 8; i++) {
            int part = ((data[i << 1] << 8) & 0xff00) | (data[(i << 1) + 1] & 0xff);

            if (part != 0) {
                builder.append(Integer.toHexString(part));
                compressedParts = 0;
            } else {
                compressedParts++;
            }

            if (i < 7 && (compressedParts == 0 || compressedParts == 1)) {
                builder.append(":");
            }
        }

        return builder.toString();
    }
}
