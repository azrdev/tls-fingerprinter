package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.virtualnetworklayer.util.Util;

import javax.annotation.Nonnull;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The set of different signs of two Fingerprint.Signatures.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public abstract class SignatureDifference {
    public static <T extends de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint>
            Set<SignDifference> fromVnlFingerprints(
            @Nonnull SignatureIdentifier signature, T.Signature left, T.Signature right) {
        Map<String, Object> leftSigns = null;
        Map<String, Object> rightSigns = null;
        if(left != null) leftSigns = left.getSigns();
        if(right != null) rightSigns = right.getSigns();

        return diff(signature, leftSigns, rightSigns);
    }

    public static <T extends Fingerprint> Set<SignDifference> fromGenericFingerprints(
            @Nonnull SignatureIdentifier signature, T left, T right) {
        Map<String, Object> leftSigns = null;
        Map<String, Object> rightSigns = null;
        if(left != null) leftSigns = left.getSigns();
        if(right != null) rightSigns = right.getSigns();

        //TODO: this ignores fuzzyness
        return diff(signature, leftSigns, rightSigns);
    }

    /**
     * Construct a SignatureDifference by iterating over common keys and creating
     * SignDifference objects according to the found differences.
     * @param signature The factory to create {@link SignIdentifier}s
     */
    private static Set<SignDifference> diff(@Nonnull SignatureIdentifier signature,
                                            Map<String, Object> leftSigns,
                                            Map<String, Object> rightSigns) {
        final Set<SignDifference> differences = new HashSet<>();

        Set<String> keys = new HashSet<>();
        if(leftSigns != null) keys.addAll(leftSigns.keySet());
        if(rightSigns != null) keys.addAll(rightSigns.keySet());

        for(String key : keys) {
            final SignIdentifier id = signature.signIdentifier(key);
            if(leftSigns != null && leftSigns.containsKey(key)) {
                final Object leftSign = leftSigns.get(key);
                if(rightSigns != null && rightSigns.containsKey(key)) {
                    final Object rightSign = rightSigns.get(key);

                    if(!Util.equal(leftSign, rightSign)) {
                        differences.add(new SignDifferenceInValue(id, leftSign, rightSign));
                    }
                } else {
                    differences.add(new SignDifferenceOnlyLeft(id, leftSign));
                }
            } else if(rightSigns != null && rightSigns.containsKey(key)) {
                final Object rightSign = rightSigns.get(key);
                differences.add(new SignDifferenceOnlyRight(id, rightSign));
            }
        }

        return differences;
    }

    public abstract static class SignDifference {
        public SignIdentifier getName() {
            return name;
        }
        public abstract Object getLeft();
        public abstract Object getRight();

        protected SignIdentifier name;

        @Override public abstract String toString();
    }

    private static class SignDifferenceOnlyLeft extends SignDifference {
        private Object leftSign;

        /**
         * Construct a SignDifference with the sign being present only on the left side
         */
        public SignDifferenceOnlyLeft(SignIdentifier name, Object leftSign) {
            this.name = name;
            this.leftSign = leftSign;
        }

        @Override
        public Object getLeft() {
            return leftSign;
        }

        @Override
        public Object getRight() {
            return null;
        }

        @Override
        public String toString() {
            return name + " only on left side: " + leftSign;
        }
    }

    private static class SignDifferenceOnlyRight extends SignDifference {
        private Object rightSign;

        /**
         * Construct a SignDifference with the sign being present only on the right side
         */
        public SignDifferenceOnlyRight(SignIdentifier name, Object rightSign) {
            this.name = name;
            this.rightSign = rightSign;
        }

        @Override
        public Object getLeft() {
            return null;
        }

        @Override
        public Object getRight() {
            return rightSign;
        }

        @Override
        public String toString() {
            return name + " only on right side: " + rightSign;
        }
    }

    private static class SignDifferenceInValue extends SignDifference {
        private Object leftSign;
        private Object rightSign;

        /**
         * Construct a SignDifference with the sign being present on both sides
         */
        public SignDifferenceInValue(SignIdentifier name, Object leftSign, Object rightSign) {
            this.name = name;
            this.leftSign = leftSign;
            this.rightSign = rightSign;
        }

        @Override
        public Object getLeft() {
            return leftSign;
        }

        @Override
        public Object getRight() {
            return rightSign;
        }

        @Override
        public String toString() {
            //TODO: List<> diff
            return name + ": " + leftSign + " <=> " + rightSign;
        }
    }

    public static class SignIdentifier implements Serializable {
        private final String signature;
        private final String sign;

        private SignIdentifier(String signature, String sign) {
            this.signature = Objects.requireNonNull(signature);
            this.sign = Objects.requireNonNull(sign);
        }

        @Override
        public String toString() {
            return signature + "." + sign;
        }

        public String getSignature() {
            return signature;
        }

        public String getSign() {
            return sign;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            SignIdentifier that = (SignIdentifier) o;

            if (!sign.equals(that.sign)) return false;
            if (!signature.equals(that.signature)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = signature.hashCode();
            result = 31 * result + sign.hashCode();
            return result;
        }
    }

    /**
     * Factory for {@link SignIdentifier}s
     */
    public static class SignatureIdentifier {
        private final String signature;

        public static SignatureIdentifier create(String signature) {
            return new SignatureIdentifier(signature);
        }

        private SignatureIdentifier(String signature) {
            this.signature = Objects.requireNonNull(signature);
        }

        public SignIdentifier signIdentifier(String sign) {
            return new SignIdentifier(signature, sign);
        }
    }
}
