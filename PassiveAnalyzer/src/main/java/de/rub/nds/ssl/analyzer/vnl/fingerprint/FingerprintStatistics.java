package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableMultiset;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import org.apache.log4j.Logger;

import java.text.DecimalFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

/**
 * Collect statistics about fingerprint reports, especially about changes.
 *
 * @author jBiegert azrdev@qrdn.de
 */
//TODO: persistent stats over multiple runs
public class FingerprintStatistics extends Observable implements FingerprintReporter {
    private static Logger logger = Logger.getLogger(FingerprintStatistics.class);
    private static final DecimalFormat percent = new DecimalFormat( "#0.0%" );

    // report counts
    public static enum ReportType { New, Update, Change, Generated }
    private Multiset<ReportType> reportCounts = HashMultiset.create(ReportType.values().length);

    // changed statistics

    //TODO: move to SignatureDifference
    public static class SignIdentifier {
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

    /** Distribution: "# of previous Fingerprints" -> count of changed reports */
    private Multiset<Number> changedPreviousCounts = HashMultiset.create();

    //FIXME: normalize these by "# of previous Fingerprints"

    /** Distribution: "# of signs in diff to previous fingerprint" -> count of "previous" fingerprints */
    private Multiset<Number> diffSize = HashMultiset.create();

    /** Distribution: sign -> count of occurrences in all changed reports */
    private Multiset<SignIdentifier> changedSignCounts = HashMultiset.create();

    // export / display / output statistics

    public void routineLogging() {
        logger.info(toString());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Fingerprint Reports: ");
        for (ReportType type : ReportType.values()) {
            final int count = reportCounts.count(type);
            sb.append(type.toString()).append(": ").append(count);
            sb.append(" (");
            sb.append(percent.format((double)count / reportCounts.size()));
            sb.append("), ");
        }
        sb.setLength(sb.length() -2);

        return sb.toString();
    }

    // calculating statistics getters

    /**
     * @return Total number of reports seen so far.
     */
    public Number getReportCount() {
        return reportCounts.size();
    }

    /**
     * @return Number of reports seen so far for given type.
     */
    public Number getReportCount(final ReportType type) {
        return reportCounts.count(type);
    }

    /**
     * @return Total count of "previous" fingerprints seen in all changed reports
     */
    public Number getDiffsToPreviousCount() {
        return diffSize.size();
    }

    /**
     * @return Average count of "previous" fingerprints seen in changed reports
     */
    public Number getDiffsToPreviousAverage() {
        return getDiffsToPreviousCount().doubleValue() / changedPreviousCounts.size();
    }

    /**
     * @return Distribution: number of "previous" fingerprints -> count of "changed" reports
     */
    public ImmutableMultiset<Number> getDiffsToPreviousDistribution() {
        return ImmutableMultiset.copyOf(changedPreviousCounts);
    }

    /**
     * @return Total count of signs seen in all diffs to "previous" fingerprints
     */
    public Number getChangedSignsCount() {
        return changedSignCounts.size();
    }

    /**
     * @return Average count of signs seen in any diff to a "previous" fingerprint
     */
    public Number getChangedSignsAverage() {
        return getChangedSignsCount().doubleValue() / getDiffsToPreviousCount().doubleValue();
    }

    /**
     * @return Distribution: Number of signs in diff -> count of "previous" fingerprints
     */
    public ImmutableMultiset<Number> getDiffSizeDistribution() {
        return ImmutableMultiset.copyOf(diffSize);
    }

    //TODO: stats about diff type: sign value / only on one side

    /**
     * @return The differing signs and how often they have been seen in any diff to a
     * "previous" fingerprint, ordered by that count
     */
    public ImmutableMultiset<SignIdentifier> getMostCommonChangedSigns() {
        return Multisets.copyHighestCountFirst(changedSignCounts);
    }

    // FingerprintReporter interface

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             Set<TLSFingerprint> previousFingerprints) {
        reportCounts.add(ReportType.Change);

        changedPreviousCounts.add(previousFingerprints.size());

        for (TLSFingerprint previousFingerprint : previousFingerprints) {
            final SetMultimap<String, SignatureDifference.SignDifference> differenceMap =
                    fingerprint.differenceMap(previousFingerprint);
            diffSize.add(differenceMap.size());
            for (Map.Entry<String, SignatureDifference.SignDifference> difference :
                    differenceMap.entries()) {
                final SignatureDifference.SignDifference value = difference.getValue();
                changedSignCounts.add(
                        new SignIdentifier(difference.getKey(), value.getName()));
            }
        }
        setChanged(); notifyObservers("Change");
    }

    @Override
    public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        reportCounts.add(ReportType.Update);
        setChanged(); notifyObservers();
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
        reportCounts.add(ReportType.New);
        setChanged(); notifyObservers();
    }

    @Override
    public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        reportCounts.add(ReportType.Generated);
        setChanged(); notifyObservers();
    }

    // singleton

    private FingerprintStatistics() {}

    private static FingerprintStatistics instance;

    public static FingerprintStatistics instance() {
        if(instance == null)
            instance = new FingerprintStatistics();
        return instance;
    }
}
