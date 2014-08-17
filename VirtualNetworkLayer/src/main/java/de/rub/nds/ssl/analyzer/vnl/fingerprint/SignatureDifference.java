package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The set of different signs of two Fingerprint.Signatures.
 * Generally assumes they are not equal.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SignatureDifference {
    private Set<SignDifference> differences = new HashSet<>();

    public static <T extends de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint>
            SignatureDifference fromVnlFingerprints(T.Signature left, T.Signature right) {
        Map<String, Object> leftSigns = null;
        Map<String, Object> rightSigns = null;
        if(left != null) leftSigns = left.getSigns();
        if(right != null) rightSigns = right.getSigns();

        return new SignatureDifference(leftSigns, rightSigns);
    }

    public static <T extends Fingerprint> SignatureDifference fromGenericFingerprints(
            T.Signature left, T.Signature right) {
        Map<String, Object> leftSigns = null;
        Map<String, Object> rightSigns = null;
        if(left != null) leftSigns = left.getSigns();
        if(right != null) rightSigns = right.getSigns();

        return new SignatureDifference(leftSigns, rightSigns);
    }

    /**
     * Construct a SignatureDifference by iterating over common keys and creating
     * SignDifference objects according to the found differences.
     */
    private SignatureDifference(Map<String, Object> leftSigns, Map<String, Object> rightSigns) {
        Set<String> keys = new HashSet<>();
        if(leftSigns != null) keys.addAll(leftSigns.keySet());
        if(rightSigns != null) keys.addAll(rightSigns.keySet());

        for(String key : keys) {
            if(leftSigns != null && leftSigns.containsKey(key)) {
                final Object leftSign = leftSigns.get(key);
                if(rightSigns != null && rightSigns.containsKey(key)) {
                    final Object rightSign = rightSigns.get(key);

                    if(!Util.equal(leftSign, rightSign)) {
                        differences.add(new SignDifferenceInValue(key, leftSign, rightSign));
                    }
                } else {
                    differences.add(new SignDifferenceOnlyLeft(key, leftSign));
                }
            } else if(rightSigns != null && rightSigns.containsKey(key)) {
                final Object rightSign = rightSigns.get(key);
                differences.add(new SignDifferenceOnlyRight(key, rightSign));
            }
        }
    }

    public Set<SignDifference> getDifferences() {
        return differences;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for(SignDifference difference : differences) {
            sb.append(difference.toString()).append("\n");
        }
        return sb.toString();
    }



    public abstract class SignDifference {
        protected String name;

        @Override public abstract String toString();
    }

    private class SignDifferenceOnlyLeft extends SignDifference {
        private Object leftSign;

        /**
         * Construct a SignDifference with the sign being present only on the left side
         */
        public SignDifferenceOnlyLeft(String name, Object leftSign) {
            this.name = name;
            this.leftSign = leftSign;
        }

        @Override
        public String toString() {
            return name + " only on left side: " + leftSign;
        }
    }

    private class SignDifferenceOnlyRight extends SignDifference {
        private Object rightSign;

        /**
         * Construct a SignDifference with the sign being present only on the right side
         */
        public SignDifferenceOnlyRight(String name, Object rightSign) {
            this.name = name;
            this.rightSign = rightSign;
        }

        @Override
        public String toString() {
            return name + " only on right side: " + rightSign;
        }
    }

    private class SignDifferenceInValue extends SignDifference {
        private Object leftSign;
        private Object rightSign;

        /**
         * Construct a SignDifference with the sign being present on both sides
         */
        public SignDifferenceInValue(String name, Object leftSign, Object rightSign) {
            this.name = name;
            this.leftSign = leftSign;
            this.rightSign = rightSign;
        }

        @Override
        public String toString() {
            //TODO: List<> diff
            return name + ": " + leftSign + " <=> " + rightSign;
        }
    }


}
