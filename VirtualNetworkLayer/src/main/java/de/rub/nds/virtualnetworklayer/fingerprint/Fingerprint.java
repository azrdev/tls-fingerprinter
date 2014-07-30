package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.util.Util;
import de.rub.nds.virtualnetworklayer.util.formatter.StringFormatter;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * A fingerprint can be registered with {@link de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler}:
 * <ul>
 * <li>add type to registy {@link de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints}</li>
 * <li>implement {@link #getId()} (for uniqueness use id from registry {@code Fingerprints.*.getId()})</li>
 * <li>implement {@link #isBound(de.rub.nds.virtualnetworklayer.packet.PcapPacket)}</li>
 * <li>
 * implement {@link #match(Fingerprint.Signature, de.rub.nds.virtualnetworklayer.packet.PcapPacket, de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection)}
 * using {@link Signature#addSign(String, Object)}. If the sign is fuzzy the passed {@code value} has to subclass
 * {@link Fuzzy} and {@link Signature#setMaximumDistance(int)} must be set.
 * </li>
 * <li>implement a signature with matching signs and register with {@link de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler}</li>
 * <li>register with {@link de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler}</li>
 * </ul>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class Fingerprint {
    public interface Fuzzy<T> extends Comparable<T> {

        public int compareTo(T other);
    }

    public static class Signature {
        private Map<String, Object> signs = new HashMap<>();
        private EnumSet<Quirk> quirks = EnumSet.noneOf(Quirk.class);
        private boolean fuzzy = false;
        private int maximumDistance = 0;
        protected int hashCode = 0;

        protected void addSign(String key, Object value) {
            signs.put(key, value);
        }

        public <T> T getSign(String key) {
            return (T) signs.get(key);
        }
        
        public Map<String, Object> getSigns() {
        	return new HashMap<>(signs);
        }

        protected void addQuirk(Quirk quirk) {
            if (!quirks.contains(quirk)) {
                quirks.add(quirk);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Signature)) {
                return false;
            }

            Signature other = (Signature) o;
            int distance = 0;

            for (Map.Entry<String, Object> entry : other.signs.entrySet()) {
                Object value = signs.get(entry.getKey());

                if (value != null && !Util.equal(value, entry.getValue())) {
                    if (!(fuzzy && value instanceof Fuzzy)) {
                        return false;
                    } else {
                        distance += ((Fuzzy) value).compareTo(entry.getValue());
                    }
                }
            }

            if (distance > maximumDistance) {
                return false;
            }

            for (Quirk quirk : other.quirks) {
                if (!quirks.contains(quirk)) {

                    /* If there is a difference in quirks, but it amounts to 'df' or 'id+'
                    disappearing, or 'id-' or 'ecn' appearing, allow a fuzzy match. */
                    if (!(fuzzy && (quirk.equals(Quirk.DF) || quirk.equals(Quirk.NZ_ID) ||
                            quirk.equals(Quirk.ZERO_ID) || quirk.equals(Quirk.ECN)))) {
                        return false;
                    }
                }
            }

            return true;
        }

        public void setFuzzy(boolean fuzzy) {
            this.fuzzy = fuzzy;
        }

        public void setMaximumDistance(int maximumDistance) {
            this.maximumDistance = maximumDistance;
        }

        public int hashCode() {
            if (hashCode != 0) {
                return hashCode;
            }

            return Arrays.hashCode(signs.values().toArray());
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("- HashCode").append(": ").append(hashCode());
            builder.append('\n');

            for (Map.Entry<String, Object> entry : signs.entrySet()) {
                Object value = entry.getValue();
                builder.append("- ");
                builder.append(StringFormatter.firstToUppercase(entry.getKey()));
                builder.append(": ").append(value.toString());
                builder.append(" [").append(value.getClass().getCanonicalName());
                builder.append("]\n");
            }

            builder.append("- Quirks: ").append(quirks.toString());
            builder.append('\n');
            builder.append("- Fuzzy: ").append(fuzzy);

            return builder.toString();
        }

    }

    public final Fingerprint.Signature peer(PcapPacket packet, PcapConnection connection) {
        Fingerprint.Signature newSignature = new Fingerprint.Signature();
        match(newSignature, packet, connection);

        return newSignature;
    }

    protected abstract void match(Fingerprint.Signature signature, PcapPacket packet, PcapConnection connection);

    /**
     * @return whether fingerprint can be matched to packet
     */
    public abstract boolean isBound(PcapPacket packet);

    /**
     * @return unique id
     */
    public abstract int getId();

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
