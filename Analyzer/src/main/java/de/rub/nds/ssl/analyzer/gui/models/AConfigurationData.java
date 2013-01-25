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

    private transient Column[] columns;
    private transient Object[][] configuration;

    protected class Column {

        private String name;
        private boolean editable;

        Column(final String name, final boolean editable) {
            this.name = name;
            this.editable = editable;
        }

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @param name the name to set
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * @return the editable
         */
        public boolean isEditable() {
            return editable;
        }

        /**
         * @param editable the editable to set
         */
        public void setEditable(boolean editable) {
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
            result = getColumns()[columnIndex].getName();

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
        if (rowIndex < getConfiguration().length
                && columnIndex < getColumns().length) {
            result = getConfiguration()[rowIndex][columnIndex];
        }

        return result;
    }

    @Override
    public boolean isCellEditable(final int rowIndex, final int columnIndex) {
        boolean result = false;

        if (columnIndex < getColumns().length) {
            result = getColumns()[columnIndex].isEditable();
        }

        return result;
    }

    @Override
    public void setValueAt(final Object aValue, final int rowIndex,
            final int columnIndex) {
        if (aValue instanceof Boolean) {
            getConfiguration()[rowIndex][columnIndex] = aValue;
        }
    }

    /**
     * Getter for columns.
     *
     * @return the columns
     */
    protected final Column[] getColumns() {
        Column[] cols = new Column[columns.length];
        System.arraycopy(columns, 0, cols, 0, columns.length);
        return columns;
    }

    /**
     * Setter for columns.
     *
     * @param columns the columns to set
     */
    protected final void setColumns(final Column[] columns) {
        this.columns = new Column[columns.length];
        System.arraycopy(columns, 0, this.columns, 0, columns.length);
    }

    /**
     * Getter for configuration array.
     *
     * @return the configuration
     */
    public final Object[][] getConfiguration() {
        Object[][] config = new Object[configuration.length][];
        System.arraycopy(configuration, 0, config, 0, configuration.length);
        return config;
    }

    /**
     * Setter for configuration.
     *
     * @param configuration the configuration to set
     */
    public final void setConfiguration(final Object[][] configuration) {
        this.configuration = new Object[configuration.length][];
        System.arraycopy(configuration, 0, this.configuration, 0,
                configuration.length);

    }
}
