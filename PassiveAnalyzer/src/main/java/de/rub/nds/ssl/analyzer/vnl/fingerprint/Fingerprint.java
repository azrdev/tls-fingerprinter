package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.FingerprintSaveFileReader;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.*;

/**
 * Fingerprinting abilities like in {@link de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint}.
 *
 * <p>The purpose of this fingerprinting is to identify individual TLS endpoints and
 * recognize them (to detect changes on identical endpoint addresses).
 *
 * Contrary to that, the fingerprinting in the virtualnetworklayer tries to assign each
 * fingerprinted endpoint to one of a set of previously known classes (with Labels -
 * see {@link de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection}).</p>
 *
 * <b>NOTE:</b> don't ever put arrays as sign values, or you'll break things
 * (e.g. <code>toString()</code> and <code>equals()</code>)
 *
 * @author jBiegert azrdev@qrdn.de
 */
public abstract class Fingerprint<F extends Fingerprint<F>> {

    protected Fingerprint() {}

    protected Fingerprint(Fingerprint original) {
        Objects.requireNonNull(original);
        this.signs = new HashMap<>(original.getSigns());
    }

    protected Map<String, Object> signs = new HashMap<>();

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
        if (!(o instanceof Fingerprint)) {
            return false;
        }

        Fingerprint other = (Fingerprint) o;

        Set<String> allSigns = new HashSet<>();
        allSigns.addAll(signs.keySet());
        allSigns.addAll(other.signs.keySet());

        for (String key : allSigns) {
            Object value = signs.get(key);
            Object oValue = other.signs.get(key);

            //NOTE: don't put arrays as sign values!
            if (! Util.equal(value, oValue)) {
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

        for(String sign : serializationSigns()) {
            Object obj = getSign(sign);
            if(obj != null)
                sb.append(Serializer.serializeSign(obj));
            sb.append(SERIALIZATION_DELIMITER);
        }

        // delete the last delimiter
        sb.setLength(sb.length() - SERIALIZATION_DELIMITER.length());

        return sb.toString();
    }

    /**
     * @return A List of all signs that should be serialized in that order.
     */
    public abstract List<String> serializationSigns();

    /**
     * Read from serialized form. Use {@link #deserialize(List)} instead.
     * @return this
     */
    @Deprecated
    protected final F deserialize(String serialized) {
        return deserialize(Arrays.asList(
                serialized.trim().split(SERIALIZATION_DELIMITER, -1)));
    }

    /**
     * Read from serialized form, signs already split.
     * @return this
     * @see FingerprintSaveFileReader
     */
    protected abstract F deserialize(final List<String> signs);
}
