package de.rub.nds.virtualnetworklayer.util;

import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public class Util {
    static {
        try {
            InputStream inputStream = Util.class.getResourceAsStream("/de/rub/nds/virtualnetworklayer/logging.properties");
            LogManager.getLogManager().readConfiguration(inputStream);
        } catch (final IOException e) {
            Logger.getAnonymousLogger().severe("Could not load default logging.properties file");
            Logger.getAnonymousLogger().severe(e.getMessage());
        }
    }

    public static <T extends Enum<T>> T readEnum(Class<T> clazz, String value) {
        for (T enumeration : clazz.getEnumConstants()) {
            if (enumeration.toString().equals(value)) {
                return enumeration;
            }
        }

        throw new IllegalArgumentException();
    }


    public static Integer readBoundedInteger(String value, int rangeBegin, int rangeEnd) {
        int integer = Integer.parseInt(value.replaceAll("[^\\d]", ""));
        if (integer < rangeBegin || integer > rangeEnd) {
            throw new IllegalArgumentException();
        }

        return integer;
    }

    public static long now() {
        return System.currentTimeMillis();
    }

    public static int hashCode(Object... objects) {
        return Arrays.hashCode(objects);
    }

    public static boolean equal(Object a, Object b) {
        return a == b || (a != null && a.equals(b));
    }

    public static int enumHashCode(List<TcpHeader.Option> enums) {
        int[] ordinals = new int[enums.size()];

        int i = 0;

        for (Enum<?> e : enums) {
            ordinals[i] = e.ordinal();
            i++;
        }

        return Arrays.hashCode(ordinals);
    }

    public static ByteBuffer clone(ByteBuffer original) {
        ByteBuffer clone = ByteBuffer.allocate(original.capacity());
        original.rewind();
        clone.put(original);
        original.rewind();
        clone.flip();

        return clone;
    }

    public static byte[] toAddress(InetAddress address) {
        return toAddress(address.toString().split("/")[1]);
    }

    public static byte[] toAddress(String ip4String) {
        byte[] address = new byte[4];
        String[] parts = ip4String.split("\\.");

        for (int i = 0; i < parts.length; i++) {
            Integer integer = Integer.parseInt(parts[i]);
            address[i] = integer.byteValue();
        }

        return address;
    }

    public static String toIp4String(byte[] data) {
        StringBuilder builder = new StringBuilder(32);

        for (int i = 0; i < 4; i++) {
            builder.append(data[i] & 0xFF);
            if (i < 3) {
                builder.append(".");
            }
        }

        return builder.toString();
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

    public static String toHexDump(byte[] buffer) {
        return toHexDump(buffer, 0, buffer.length);
    }


}
