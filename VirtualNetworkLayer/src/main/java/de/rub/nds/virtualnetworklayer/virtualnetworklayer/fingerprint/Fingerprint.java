package de.rub.nds.virtualnetworklayer.fingerprint;

import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public abstract class Fingerprint {

    public static class Signature extends de.rub.nds.virtualnetworklayer.util.Signature {

        private HashMap<String, Object> signs = new HashMap<String, Object>();
        private EnumSet<Quirk> quirks = EnumSet.noneOf(Quirk.class);
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

            for (Map.Entry<String, Object> entry : other.signs.entrySet()) {
                Object value = signs.get(entry.getKey());
                //System.out.println(entry.getKey() + " " + entry.getValue() + " " + value);
                if (value == null || !value.toString().equals(entry.getValue().toString())) {
                    return false;

                }
            }

            for (Quirk quirk : other.quirks) {
                //System.out.println(quirk + " true "+quirks.contains(quirk));

                if (!quirks.contains(quirk)) {
                    return false;
                }
            }

            return true;
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
}
