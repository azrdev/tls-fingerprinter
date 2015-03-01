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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

/**
 * Collect statistics about fingerprint reports, especially about changes.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintStatistics extends Observable implements FingerprintReporter {
    private static Logger logger = Logger.getLogger(FingerprintStatistics.class);
    private static final DecimalFormat percent = new DecimalFormat( "#0.0%" );

    // report counts
    public enum ReportType { New, Update, Change, Generated };
    private Multiset<ReportType> reportCounts = HashMultiset.create(ReportType.values().length);

    // changed statistics

    //TODO: move to SignatureDifference
    private class SignIdentifier {
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
    private Multiset<Integer> changedPreviousCounts = HashMultiset.create();

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
    public int getReportCount() {
        return reportCounts.size();
    }

    /**
     * @return Number of reports seen so far for given type.
     */
    public int getReportCount(final ReportType type) {
        return reportCounts.count(type);
    }

    /**
     * @return Total count of "previous" fingerprints seen in all changed reports
     */
    public int getDiffsToPreviousCount() {
        return changedPreviousCounts.size();
    }

    /**
     * @return Average count of "previous" fingerprints seen in changed reports
     */
    public double getDiffsToPreviousAverage() {
        /*
        double mean = 0;
        for (Multiset.Entry<Integer> entry : changedPreviousCounts.entrySet()) {
            mean += entry.getElement() * entry.getCount();
        }
        return mean;
        */
        return getDiffsToPreviousCount() / (double) getReportCount(ReportType.Change);
    }

    /**
     * @return Distribution number of "previous" fingerprints -> count of "changed" reports
     */
    public ImmutableMultiset<Integer> getDiffsToPreviousDistribution() {
        return ImmutableMultiset.copyOf(changedPreviousCounts);
    }

    /**
     * @return Total count of signs seen in all diffs to "previous" fingerprints
     */
    public int getChangedSignsCount() {
        return changedSignCounts.size();
    }

    /**
     * @return Average count of signs seen in any diff to a "previous" fingerprint
     */
    public double getChangedSignsAverage() {
        return (double) getChangedSignsCount() / getDiffsToPreviousCount();
    }

    /**
     * @return Total count of "previous" fingerprints differing in only one sign to the "changed" fingerprint
     */
    public int getOnlyOneChangedSignCount() {
        return changedSignCounts.count(1);
    }

    //TODO: stats about  sign diffs / only on one side

    /**
     * @return The differing signs and how often they have been seen in any diff to a
     * "previous" fingerprint, ordered by that count
     * @param number Limit result to that many signs. May still be less
     */
    public ImmutableMultiset<SignIdentifier> getMostCommonChangedSigns(final int number) {
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
