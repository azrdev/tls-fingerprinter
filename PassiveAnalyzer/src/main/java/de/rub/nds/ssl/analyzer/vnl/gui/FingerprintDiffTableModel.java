package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.collect.Ordering;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.SortedSetMultimap;
import com.google.common.collect.TreeMultimap;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.SignatureDifference;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import org.apache.log4j.Logger;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Adapter for {@link JTable} to display diff of two {@link TLSFingerprint}s.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintDiffTableModel extends AbstractTableModel {
    private static final Logger logger = Logger.getLogger(FingerprintDiffTableModel.class);

    private final TLSFingerprint baseFingerprint;
    private TLSFingerprint diffTarget;
    private List<DifferenceRow> differences = new ArrayList<>();

    public FingerprintDiffTableModel(TLSFingerprint baseFingerprint) {
        Objects.requireNonNull(baseFingerprint);
        this.baseFingerprint = baseFingerprint;
    }

    public void setDiffTarget(TLSFingerprint diffTarget) {
        this.diffTarget = diffTarget;
        differences.clear();
        for (Map.Entry<String, SignatureDifference.SignDifference> difference :
                baseFingerprint.differenceMap(diffTarget).entries()) {
            final SignatureDifference.SignDifference signDiff = difference.getValue();
            differences.add(new DifferenceRow(difference.getKey(),
                    signDiff.getName(),
                    signDiff.getLeft(),
                    signDiff.getRight()));
        }

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

        final DifferenceRow dr = differences.get(row);
        switch(column) {
            case 0: return dr.fingerprint + "." + dr.sign;
            case 1: return dr.base;
            case 2: return dr.target;
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

    private class DifferenceRow {
        String fingerprint;
        String sign;
        Object base;
        Object target;

        public DifferenceRow(String fingerprint, String sign, Object base, Object target) {
            this.fingerprint = fingerprint;
            this.sign = sign;
            this.base = base;
            this.target = target;
        }
    }
}
