package de.rub.nds.ssl.analyzer.gui;

import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import javax.swing.table.AbstractTableModel;

/**
 * Table model for scanner configuration.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 15, 2013
 */
public class ScannerConfigurationData extends AbstractTableModel {

    private Column[] columns = new Column[]{
        new Column("Component", false),
        new Column("Enabled", true)
    };
    private Object[][] configuration;

    private class Column {

        private String name;
        private boolean editable;

        Column(final String name, final boolean editable) {
            this.name = name;
            this.editable = editable;
        }
    }

    @SuppressWarnings("empty-statement")
    public ScannerConfigurationData() {
        EFingerprintTests[] tests = EFingerprintTests.values();
        configuration = new Object[tests.length][];
        for (int i = 0; i < tests.length; i++) {
            configuration[i] = new Object[]{tests[i].getDescription(), true,
                tests[i]};
        }
    }

    @Override
    public String getColumnName(final int columnIndex) {
        String result = null;
        if (columnIndex < columns.length) {
            result = columns[columnIndex].name;

        }

        return result;
    }

    @Override
    public int getRowCount() {
        return configuration.length;
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    /**
     * Determine the default cell editor/renderer. - e.g., automatically adds
     * checkboxes for boolean types.
     */
    @Override
    public Class getColumnClass(final int c) {
        return getValueAt(0, c).getClass();
    }

    @Override
    public Object getValueAt(final int rowIndex, final int columnIndex) {
        Object result = null;
        if (rowIndex < configuration.length && columnIndex < columns.length) {
            result = configuration[rowIndex][columnIndex];
        }

        return result;
    }

    @Override
    public boolean isCellEditable(final int rowIndex, final int columnIndex) {
        boolean result = false;

        if (columnIndex < columns.length) {
            result = columns[columnIndex].editable;
        }

        return result;
    }

    @Override
    public void setValueAt(final Object aValue, final int rowIndex,
            final int columnIndex) {
        if(aValue instanceof Boolean) {
            configuration[rowIndex][columnIndex] = aValue;
        }
    }
}
