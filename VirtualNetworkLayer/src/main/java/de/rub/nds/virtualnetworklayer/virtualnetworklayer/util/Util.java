package de.rub.nds.virtualnetworklayer.util;

import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class Util {

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

    public static String toIp4String(final byte[] data) {
        StringBuilder builder = new StringBuilder(32);

        for (int i = 0; i < 4; i++) {
            builder.append(data[i] & 0xFF);
            if (i < 3) {
                builder.append(".");
            }
        }

        return builder.toString();
    }

}
