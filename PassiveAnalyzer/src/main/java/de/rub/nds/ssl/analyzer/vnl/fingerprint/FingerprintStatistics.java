package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableMultiset;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import org.apache.log4j.Logger;

import java.io.Serializable;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

/**
 * Collect statistics about fingerprint reports, especially about changes.
 *
 * @author jBiegert azrdev@qrdn.de
 */
//TODO: maybe use an outside-readable serialization instead of Serializable/JOS
public final class FingerprintStatistics
        extends Observable
        implements FingerprintReporter, Serializable {
    public static final long serialVersionUID = 1L;
    private static final DecimalFormat percent = new DecimalFormat( "#0.0%" );

    private static final Logger logger = Logger.getLogger(FingerprintStatistics.class);

    // report counts
    public static enum ReportType { New, Update, Change, Generated }
    private Multiset<ReportType> reportCounts = HashMultiset.create(ReportType.values().length);

    // changed statistics

    //TODO: move to SignatureDifference
    public static class SignIdentifier implements Serializable {
        private final String signature;
        private final String sign;

        public SignIdentifier(String signature, String sign) {
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

    /**
     * Write statistics to log.
     * @param verbose Include all captured values
     */
    public void log(boolean verbose) {
        logger.info(toString());
        if(verbose) {
            final NumberFormat frac = new DecimalFormat("#");
            frac.setMaximumFractionDigits(2);
            StringBuilder sb = new StringBuilder("Detailed statistics: \n");

            sb.append("previous[] size -> changed report count: ")
                    .append("Total ").append(changedPreviousCounts.size()).append(" ")
                    .append(getDiffsToPreviousDistribution().toString()).append(" \n");
            sb.append("Average count of previous fingerprints seen per changed report: ")
                    .append(frac.format(getDiffsToPreviousAverage())).append(" \n");
            sb.append("diff size -> previous fingerprint count: ")
                    .append("Total ").append(diffSize.size()).append(" ")
                    .append(getDiffSizeDistribution().toString()).append(" \n");
            sb.append("Average count of signs seen per diff to any previous fingerprint: ")
                    .append(frac.format(getChangedSignsAverage())).append(" \n");
            sb.append("sign counts: ")
                    .append("Total ").append(changedSignCounts.size()).append(" ")
                    .append(getMostCommonChangedSigns().toString()).append(" \n");
            logger.info(sb.toString());
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Fingerprint Reports - Total: ");
        sb.append(getReportCount()).append(", ");
        for (ReportType type : ReportType.values()) {
            final Number count = getReportCount(type);
            sb.append(type.toString()).append(": ").append(count).append(" (");
            sb.append(percent.format(count.doubleValue() / reportCounts.size()));
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
}
