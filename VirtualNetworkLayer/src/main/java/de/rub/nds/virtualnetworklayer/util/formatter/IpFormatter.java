package de.rub.nds.virtualnetworklayer.util.formatter;

public class IpFormatter extends StringFormatter {

    public static String toString(byte[] data) {
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
