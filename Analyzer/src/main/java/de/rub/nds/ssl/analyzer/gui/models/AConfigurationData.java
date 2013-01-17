package de.rub.nds.ssl.analyzer.gui.models;

import javax.swing.table.AbstractTableModel;

/**
 * Abstract table model for configuration data.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public class AConfigurationData extends AbstractTableModel {

    private Column[] columns;
    private Object[][] configuration;

    protected class Column {

        private String name;
        private boolean editable;

        Column(final String name, final boolean editable) {
            this.name = name;
            this.editable = editable;
        }
    }

    @SuppressWarnings("empty-statement")
    public AConfigurationData() {
        
    }

    @Override
    public String getColumnName(final int columnIndex) {
        String result = null;
        if (columnIndex < getColumns().length) {
            result = getColumns()[columnIndex].name;

        }

        return result;
    }

    @Override
    public int getRowCount() {
        return getConfiguration().length;
    }

    @Override
    public int getColumnCount() {
        return getColumns().length;
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
        if (rowIndex < getConfiguration().length && columnIndex < getColumns().length) {
            result = getConfiguration()[rowIndex][columnIndex];
        }

        return result;
    }

    @Override
    public boolean isCellEditable(final int rowIndex, final int columnIndex) {
        boolean result = false;

        if (columnIndex < getColumns().length) {
            result = getColumns()[columnIndex].editable;
        }

        return result;
    }

    @Override
    public void setValueAt(final Object aValue, final int rowIndex,
            final int columnIndex) {
        if(aValue instanceof Boolean) {
            getConfiguration()[rowIndex][columnIndex] = aValue;
        }
    }
    
        /**
     * Getter for columns.
     * @return the columns
     */
    public Column[] getColumns() {
        return columns;
    }

    /**
     * Setter for columns.
     * @param columns the columns to set
     */
    public void setColumns(final Column[] columns) {
        this.columns = columns;
    }

    /**
     * Getter for configuration array.
     * @return the configuration
     */
    public Object[][] getConfiguration() {
        return configuration;
    }

    /**
     * Setter for configuration.
     * @param configuration the configuration to set
     */
    public void setConfiguration(final Object[][] configuration) {
        this.configuration = configuration;
    }
}
