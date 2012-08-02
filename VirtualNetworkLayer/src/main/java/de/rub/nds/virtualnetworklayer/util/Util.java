package de.rub.nds.virtualnetworklayer.util;

import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Utility class
 * </p>
 * Using all static methods enforces the class to have no state.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class Util {

    private Util() {
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
        return address.getAddress();
    }

    public static String getDefaultRoute() {

        try {
            Process result = Runtime.getRuntime().exec("netstat -rn");

            BufferedReader reader = new BufferedReader(new InputStreamReader(result.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("default")) {
                    StringTokenizer tokenizer = new StringTokenizer(line);
                    tokenizer.nextToken();
                    tokenizer.nextToken();
                    tokenizer.nextToken();
                    tokenizer.nextToken();
                    tokenizer.nextToken();

                    return tokenizer.nextToken();
                }
            }

        } catch (IOException e) {

        }

        return null;
    }
}
