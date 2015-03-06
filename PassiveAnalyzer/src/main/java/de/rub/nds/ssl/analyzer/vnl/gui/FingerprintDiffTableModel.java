package de.rub.nds.ssl.analyzer.vnl.gui;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.SignatureDifference.SignDifference;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Adapter for {@link JTable} to display diff of two {@link TLSFingerprint}s.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintDiffTableModel extends AbstractTableModel {
    private final TLSFingerprint baseFingerprint;
    private TLSFingerprint diffTarget;
    private List<SignDifference> differences = Collections.emptyList();

    public FingerprintDiffTableModel(TLSFingerprint baseFingerprint) {
        Objects.requireNonNull(baseFingerprint);
        this.baseFingerprint = baseFingerprint;
    }

    public void setDiffTarget(TLSFingerprint diffTarget) {
        this.diffTarget = diffTarget;
        differences = new ArrayList<>(baseFingerprint.difference(diffTarget));

        fireTableDataChanged();
    }

    public TLSFingerprint getDiffTarget() {
        return diffTarget;
    }

    public TLSFingerprint getBaseFingerprint() {
        return baseFingerprint;
    }

    // AbstractTableModel interface

    @Override
    public int getRowCount() {
        return differences.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if(0 > row || row >= differences.size())
            return null;

        final SignDifference diff = differences.get(row);
        switch(column) {
            case 0: return diff.getName();
            case 1: return diff.getLeft();
            case 2: return diff.getRight();
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch(column) {
            case 0: return "sign";
            case 1: return "new fingerprint";
            case 2: return "old fingerprint";
            default: return super.getColumnName(column);
        }
    }
}
