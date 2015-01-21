package de.rub.nds.ssl.analyzer.vnl.gui;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class MessageListModel extends AbstractTableModel {
    private MessageListAppender appender = new MessageListAppender();

    private enum Columns {
        DATE("Date", Date.class),
        LEVEL("LogLevel", Level.class),
        LOGGER("Logger (Class)", String.class),
        MESSAGE("Message", String.class);

        final String name;
        final Class<?> type;
        private Columns(String name, Class<?> type) {
            this.name = name;
            this.type = type;
        }
    }

    /**
     * @return The singleton Appender instance belonging to this MessageListModel
     */
    public AppenderSkeleton getAppender() {
        return appender;
    }

    public void clear() {
        appender.clear();
    }

    @Override
    public String getColumnName(int column) {
        if(0 > column || column >= Columns.values().length)
            return null;
        return Columns.values()[column].name;
    }

    @Override
    public int getRowCount() {
        return appender.size();
    }

    @Override
    public int getColumnCount() {
        return Columns.values().length;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return Columns.values()[columnIndex].type;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if(appender == null)
            return null;
        if(0 > row || row >= appender.size())
            return null;

        return mapValue(appender.event(row), Columns.values()[column]);
    }

    private Object mapValue(LoggingEvent event, Columns col) {
        switch(col) {
            case DATE: return new Date(event.getTimeStamp());
            case LEVEL: return event.getLevel();
            case LOGGER: return event.getLoggerName();
            case MESSAGE: return event.getMessage();
            default: return null;
        }
    }

    class MessageListAppender extends AppenderSkeleton {
        private List<LoggingEvent> events = new ArrayList<>(10000);

        MessageListAppender() {
            setThreshold(Logger.getRootLogger().getLevel());
            //TODO: load older log messages
        }

        /** {@inheritDoc} */
        @Override
        protected void append(LoggingEvent loggingEvent) {
            //TODO: expire log entries, to avoid the list growing infinitely
            events.add(loggingEvent);
            fireTableRowsInserted(events.size() -1, events.size() -1);
        }

        /** flushes the list, but does not set <code>closed</code> */
        @Override
        public void close() {
            clear();
        }

        /** {@inheritDoc} */
        @Override
        public boolean requiresLayout() {
            return false;
        }

        public int size() {
            return events.size();
        }

        /** Flushes the list */
        public void clear() {
            events.clear();
            fireTableDataChanged();
        }

        public LoggingEvent event(int index) throws IndexOutOfBoundsException {
            return events.get(index);
        }
    }
}
