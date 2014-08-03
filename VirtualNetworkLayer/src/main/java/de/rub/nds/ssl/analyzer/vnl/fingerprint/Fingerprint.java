package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.StringFormatter;

import java.util.*;

/**
 * Fingerprinting abilities like in {@link de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint}.
 *
 * <p>A fingerprint defines properties to check (i.e. distinguish between Client / Server),
 * to apply this to a connection and  identify some endpoint you need a {@link Signature}</p>
 *
 * <p>The purpose of this fingerprinting is to identify individual TLS endpoints and
 * recognize them (to detect changes on identical endpoint addresses).
 *
 * Contrary to that, the fingerprinting in the virtualnetworklayer tries to assign each
 * fingerprinted endpoint to one of a set of previously known classes (with Labels -
 * see {@link de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection}).</p>
 *
 * @author jBiegert azrdev@qrdn.de
 */
public abstract class Fingerprint {

    /**
     * The instance of a {@link Fingerprint}, merely a set of signs (specific to that
     * fingerprint) and associated values (specific to the endpoint).
     */
    public static class Signature {
        private Map<String, Object> signs = new HashMap<>();

        protected void addSign(String key, Object value) {
            signs.put(key, value);
        }

        public <T> T getSign(String key) {
            return (T) signs.get(key);
        }

        public Map<String, Object> getSigns() {
        	return new HashMap<>(signs);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Signature)) {
                return false;
            }

            Signature other = (Signature) o;

            for (Map.Entry<String, Object> entry : other.signs.entrySet()) {
                Object value = signs.get(entry.getKey());

                if(value == null)
                    continue;

                //TODO: arrays unequal?
                if (! Util.equal(value, entry.getValue())) {
                    return false;
                }
            }

            return true;
        }

        public int hashCode() {
            return Arrays.hashCode(signs.values().toArray());
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            //builder.append("- HashCode: ").append(hashCode()).append('\n');

            for (Map.Entry<String, Object> entry : signs.entrySet()) {
                Object value = entry.getValue();
                builder.append("- ").append(entry.getKey()).append(": ");
                builder.append(signToString(value));
                builder.append(" [").append(value.getClass().getCanonicalName());
                builder.append("]\n");
            }

            return builder.toString();
        }

        /**
         * @return a String representation of all signs that are changed w.r.t. other
         * @param name text to represent "this"
         * @param otherName text to represent other
         */
        public String difference(Signature other,
                                 final String name, final String otherName) {
            StringBuilder sb = new StringBuilder();

            Set<String> allKeys = new HashSet<>(signs.keySet());
            allKeys.addAll(other.getSigns().keySet());

            for(String key : allKeys) {
                if(signs.containsKey(key) && other.getSigns().containsKey(key)) {
                    final Object value = signs.get(key);
                    final Object otherValue = other.getSigns().get(key);
                    if(! signCompare(value, otherValue)) {
                        sb.append("Different ").append(key).append(": ");
                        //TODO: array diff
                        sb.append(signToString(value)).append(" <=> ");
                        sb.append(signToString(otherValue)).append("\n");
                    }
                } else if(signs.containsKey(key)) {
                    sb.append("Only in ").append(name).append(": ");
                    sb.append(key).append("\n");
                } else {
                    sb.append("Only in ").append(otherName).append(": ").append(key);
                    sb.append("\n");
                }
            }

            return sb.toString();
        }

        private boolean signCompare(Object value, Object otherValue) {
            if(value == otherValue)
                return true;
            if(value == null || otherValue == null)
                return false;
            if(value instanceof Object[]) {
                if(otherValue instanceof Object[]) {
                    return Arrays.equals((Object[]) value, (Object[]) otherValue);
                }
                return false;
            }
            return value.equals(otherValue);
        }

        private String signToString(Object value) {
            if(value == null)
                return "null";
            if(value instanceof Object[])
                return Arrays.toString((Object[]) value);
            return value.toString();
        }
    }

    /**
     * Apply this fingerprint to the connection
     *
     * @see de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint#peer(de.rub.nds.virtualnetworklayer.packet.PcapPacket, de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection)
     *
     * @return a Signature comparable to others of this Fingerprint.
     */
    public final Signature createSignature(Connection connection)  {
        Signature s = new Signature();
        apply(s, connection);

        return s;
    }

    /**
     * Create a Signature from parsed Connection data.
     *
     * @see de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint#match(de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature, de.rub.nds.virtualnetworklayer.packet.PcapPacket, de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection)
     *
     * @param signature reference to add signs to
     * @param connection the parsed messages including SSL Stack datastructures
     */
    protected abstract void apply(Signature signature, Connection connection);

    /**
     * Check if the Connection contains communication this Fingerprint can be applied to.
     *
     * @see de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint#isBound(de.rub.nds.virtualnetworklayer.packet.PcapPacket)
     */
    public abstract boolean canApply(Connection connection);

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
