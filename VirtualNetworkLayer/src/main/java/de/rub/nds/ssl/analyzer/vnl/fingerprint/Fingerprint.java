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

        /**
         * Add a sign "key" to this Signature
         * @param value may be null, but must not be an array,
         *              use {@link java.util.List} instead!
         */
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
                builder.append("- ").append(entry.getKey()).append(": ").append(value);
                builder.append(" [").append(value.getClass().getCanonicalName());
                builder.append("]\n");
            }

            return builder.toString();
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
