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
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintReportModel
        extends AbstractTableModel
        implements FingerprintReporter {
    private boolean showUpdates = true;
    private boolean showNew = true;
    private boolean showArtificial = true;

    private List<Report> reports = new ArrayList<>();

    abstract static class Report {
        final Date dateTime;
        final SessionIdentifier sessionIdentifier;
        final TLSFingerprint tlsFingerprint;

        Report(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            this.sessionIdentifier = sessionIdentifier;
            this.tlsFingerprint = tlsFingerprint;
            dateTime = new Date();
        }

        public abstract String typeString();
    }

    private static class NewReport extends Report {
        NewReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public String typeString() {
            return "New";
        }
    }
    private static class UpdateReport extends Report {
        UpdateReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public String typeString() {
            return "Update";
        }
    }
    private static class ArtificialReport extends Report {
        ArtificialReport(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            super(sessionIdentifier, tlsFingerprint);
        }

        @Override
        public String typeString() {
            return "Guess";
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
        public String typeString() {
            return "Change";
        }
    }

    public static FingerprintReportModel getModel(FingerprintListener backend) {
        return new FingerprintReportModel(backend);
    }

    private FingerprintReportModel(FingerprintListener backend) {
        backend.addFingerprintReporter(this);
    }

    public boolean getShowNew() {
        return showNew;
    }

    public boolean getShowUpdates() {
        return showUpdates;
    }

    public boolean getShowArtificial() {
        return showArtificial;
    }

    public void setShowUpdates(boolean showUpdates) {
        this.showUpdates = showUpdates;
    }

    public void setShowNew(boolean showNew) {
        this.showNew = showNew;
    }

    public void setShowArtificial(boolean showArtificial) {
        this.showArtificial = showArtificial;
    }

    @Nullable
    public JFrame showReportItem(int row) {
        final Report report;
        try {
            report = reports.get(row);
        } catch(IndexOutOfBoundsException e) {
            return null;
        }
        return new FingerprintReportWindow(report);
    }

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
        if(showUpdates)
            addReport(new UpdateReport(sessionIdentifier, fingerprint));
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
        if(showNew)
            addReport(new NewReport(sessionIdentifier, tlsFingerprint));
    }

    @Override
    public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        if(showArtificial)
            addReport(new ArtificialReport(sessionIdentifier, fingerprint));
    }

    private void addReport(Report report) {
        reports.add(0, report);
        fireTableRowsInserted(0,0);
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
                return report.typeString();
            case SERVER_NAME:
                return report.sessionIdentifier.getServerHostName();
            case CLIENT_HELLO:
                return report.sessionIdentifier.getClientHelloSignature();
            default:
                return null;
        }
    }

    private enum Columns {
        TIME("Time"),
        TYPE("Type"),
        SERVER_NAME("Host"),
        CLIENT_HELLO("Client Hello");

        private String name;
        private Columns(String name) {
            this.name = name;
        }
    }
}
