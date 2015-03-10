package de.rub.nds.virtualnetworklayer.util;

import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class
 * <p>
 * Using all static methods enforces the class to have no state.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class Util {

    private Util() {}

    public static <T extends Enum<T>> T readEnum(Class<T> clazz, String value) {
        for (T enumeration : clazz.getEnumConstants()) {
            if (enumeration.toString().equals(value)) {
                return enumeration;
            }
        }

        throw new IllegalArgumentException("Could not read enum constant of type " +
            clazz.getSimpleName() + " for value " + value);
    }


    public static Integer readBoundedInteger(String value, int rangeBegin, int rangeEnd) {
        int integer = Integer.parseInt(value.replaceAll("[^\\d]", ""));
        if (integer < rangeBegin || integer > rangeEnd) {
            throw new IllegalArgumentException(
                    String.format("Integer %d out of range [%d:%d]",
                                  integer, rangeBegin, rangeEnd));
        }

        return integer;
    }

    public static long now() {
        return System.nanoTime();
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
            ordinals[i] = (e != null)? e.ordinal() : 0;
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
    	return getDefaultRoute("8.8.8.8");
    }
    
    public static String getDefaultRoute(String host) {
        return getDefaultDevice(host).getName();
    }

    public static NetworkInterface getDefaultDevice(String host) {
        try {
            DatagramSocket s = new DatagramSocket();
            try {
                s.connect(InetAddress.getByName(host), 0);
                final NetworkInterface defaultInterface = NetworkInterface.getByInetAddress(s.getLocalAddress());
                return defaultInterface;
            } finally {
                s.close();
            }
        } catch (Exception e) {
        	e.printStackTrace();
        }

        return null;
    }
}
