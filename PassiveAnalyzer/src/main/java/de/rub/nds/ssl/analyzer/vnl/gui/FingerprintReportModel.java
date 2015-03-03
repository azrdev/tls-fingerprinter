package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.collect.ImmutableSet;
import de.rub.nds.ssl.analyzer.vnl.FingerprintListener;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import javax.annotation.Nullable;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * A model for {@link JTable} listing the reports it receives as a {@link FingerprintReporter}.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintReportModel
        extends AbstractTableModel
        implements FingerprintReporter {

    private List<Report> reports = new ArrayList<>();

    public enum ReportType implements Comparable<ReportType> {
        New,
        Update,
        Guess,
        Change
    }

    abstract static class Report {
        final Date dateTime;
        final SessionIdentifier sessionIdentifier;
        final TLSFingerprint tlsFingerprint;

        Report(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            this.sessionIdentifier = sessionIdentifier;
            this.tlsFingerprint = tlsFingerprint;
            dateTime = new Date();
        }

        public abstract ReportType type();
    }

    private static class NewReport extends Report {
        NewReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public ReportType type() {
            return ReportType.New;
        }
    }
    private static class UpdateReport extends Report {
        UpdateReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public ReportType type() {
            return ReportType.Update;
        }
    }
    private static class ArtificialReport extends Report {
        ArtificialReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public ReportType type() {
            return ReportType.Guess;
        }
    }
    static class ChangedReport extends Report {
        final ImmutableSet<TLSFingerprint> previousFingerprints;
        ChangedReport(SessionIdentifier sessionIdentifier,
                      TLSFingerprint tlsFingerprint,
                      ImmutableSet<TLSFingerprint> previousFingerprints) {
            super(sessionIdentifier, tlsFingerprint);
            this.previousFingerprints = previousFingerprints;
        }

        @Override
        public ReportType type() {
            return ReportType.Change;
        }
    }

    public static FingerprintReportModel getModel(FingerprintListener backend) {
        return new FingerprintReportModel(backend);
    }

    private FingerprintReportModel(FingerprintListener backend) {
        backend.addFingerprintReporter(this);
    }

    /**
     * Create and Display a {@link FingerprintReportWindow} showing the details of the
     * indicated record. <b>NOTE</b>: Only call from Event Dispatch Thread!
     * @param row The index of the report to be shown
     * @return A reference to the created {@link FingerprintReportWindow}, or null
     */
    @Nullable
    public JFrame showReportItem(int row) {
        final Report report;
        try {
            report = reports.get(row); // this is not thread-safe
        } catch(IndexOutOfBoundsException e) {
            return null;
        }
        return new FingerprintReportWindow(report);
    }

    /**
     * Clear the list of stored records.
     * <b>NOTE</b>: Only call from Event Dispatch Thread!
     */
    public void flushReports() {
        reports.clear();
        fireTableDataChanged();
    }

    // FingerprintReporter interface

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             Set<TLSFingerprint> previousFingerprints) {
        addReport(new ChangedReport(sessionIdentifier, fingerprint,
                ImmutableSet.copyOf(previousFingerprints)));
    }

    @Override
    public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        addReport(new UpdateReport(sessionIdentifier, fingerprint));
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
        addReport(new NewReport(sessionIdentifier, tlsFingerprint));
    }

    @Override
    public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        addReport(new ArtificialReport(sessionIdentifier, fingerprint));
    }

    private void addReport(final Report report) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                reports.add(0, report);
                fireTableRowsInserted(0, 0);
            }
        });
    }

    // AbstractTableModel interface

    @Override
    public int getRowCount() {
        return reports.size();
    }

    @Override
    public int getColumnCount() {
        return Columns.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return Columns.values()[column].name;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if(0 > row || row >= reports.size())
            return null;

        final Report report = reports.get(row);
        switch (Columns.values()[column]) {
            case TIME:
                return report.dateTime;
            case TYPE:
                return report.type();
            case SERVER_NAME:
                return report.sessionIdentifier.getServerHostName();
            case CLIENT_HELLO:
                return report.sessionIdentifier.getClientHelloSignature();
            default:
                return null;
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return Columns.values()[columnIndex].type;
    }

    private enum Columns {
        TIME("Time", Date.class),
        TYPE("Type", ReportType.class),
        SERVER_NAME("Host", String.class),
        CLIENT_HELLO("Client Hello", String.class);

        private String name;
        private Class<?> type;
        private Columns(String name, Class<?> type) {
            this.name = name;
            this.type = type;
        }
    }
}
