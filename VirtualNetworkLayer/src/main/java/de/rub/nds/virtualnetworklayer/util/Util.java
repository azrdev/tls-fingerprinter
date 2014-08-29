package de.rub.nds.virtualnetworklayer.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import com.google.common.net.InetAddresses;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;

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

    public static String ipAddressToString(byte[] ipAddress) {
        return IpFormatter.toString(ipAddress);
    }

    public static byte[] ipAddressFromString(String src) {
        return InetAddresses.forString(src).getAddress();
    }

    public static byte[] toAddress(InetAddress address) {
        return address.getAddress();
    }

    public static String getDefaultRoute() {
    	return getDefaultRoute("8.8.8.8");
    }
    
    public static String getDefaultRoute(String host) {

        try {
        	/**
        	 * This will get the device that routes to 8.8.8.8, which is hopefully
        	 * the device with the default route.
        	 */
            Process result = Runtime.getRuntime().exec(new String[] {"sh", "-c", "ip -4 route get " + host + " | head -n 1 | perl -pe \"s/.*dev (\\S+)\\s*.*/\\$1/\"" });

            BufferedReader reader = new BufferedReader(new InputStreamReader(result.getInputStream()));

            String route = reader.readLine().trim();
            return route;

        } catch (Exception e) {
        	e.printStackTrace();
        }

        return null;
    }
}
