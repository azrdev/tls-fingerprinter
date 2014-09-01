package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fingerprinting abilities like in {@link de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint}.
 * TODO: update doc
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
     * LinkedHashMap -> insertion-ordered
     * this keeps the order of serialization and deserialization consistent
     */
    private Map<String, Object> signs = new LinkedHashMap<>();

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
        return new LinkedHashMap<>(signs);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Fingerprint)) {
            return false;
        }

        Fingerprint other = (Fingerprint) o;

        for (Map.Entry<String, Object> entry : other.signs.entrySet()) {
            Object value = signs.get(entry.getKey());

            //NOTE: don't put arrays as sign values!
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

    public static final String SERIALIZATION_DELIMITER = ":";

    /**
     * @return a re-readable String representation of signature.
     * @see #SERIALIZATION_DELIMITER
     */
    public String serialize() {
        StringBuilder sb = new StringBuilder();

        for(String sign : signs.keySet()) {
            Object obj = getSign(sign);
            sb.append(Serializer.serializeSign(obj)).append(SERIALIZATION_DELIMITER);
        }

        // delete the last delimiter
        sb.setLength(sb.length() - SERIALIZATION_DELIMITER.length());

        return sb.toString();
    }

    public abstract void deserialize(String serialized);
}
