package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public abstract class Fingerprint {
    public static class Signature extends de.rub.nds.virtualnetworklayer.util.Signature {
        private final static Logger logger = Logger.getLogger(Signature.class.getName());

        private HashMap<String, Object> signs = new HashMap<String, Object>();
        private EnumSet<Quirk> quirks = EnumSet.noneOf(Quirk.class);
        private boolean fuzzy = false;
        protected int hashCode = 0;

        protected void addSign(String key, Object value) {
            signs.put(key, value);
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
                logger.fine(entry.getKey() + " " + entry.getValue() + " " + value);

                if (value == null || !value.equals(entry.getValue())) {
                    if (!(fuzzy && value instanceof Comparable)) {
                        return false;
                    } else {
                        distance += ((Comparable) value).compareTo(entry.getValue());
                    }
                }
            }

            if (distance > 56) {
                return false;
            }

            for (Quirk quirk : other.quirks) {
                logger.fine(quirk + " true " + quirks.contains(quirk));

                if (!quirks.contains(quirk)) {
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

        public int hashCode() {
            if (hashCode != 0) {
                return hashCode;
            }

            return Arrays.hashCode(signs.values().toArray());
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("hashCode").append(" ").append(hashCode());
            builder.append('\n');

            for (Map.Entry<String, Object> entry : signs.entrySet()) {
                builder.append(entry.getKey()).append(" ").append(entry.getValue().toString());
                builder.append('\n');
            }

            builder.append("quirks ").append(quirks.toString());

            return builder.toString();
        }

    }

    public Fingerprint.Signature peer(PcapPacket packet) {
        Fingerprint.Signature newSignature = new Fingerprint.Signature();
        match(newSignature, packet);

        return newSignature;
    }

    public abstract void match(Fingerprint.Signature signature, PcapPacket packet);

    public abstract boolean isBound(PcapPacket packet);

    public abstract int getId();
}
