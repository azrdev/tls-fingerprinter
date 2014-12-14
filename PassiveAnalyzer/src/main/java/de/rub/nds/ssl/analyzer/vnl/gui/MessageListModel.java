package de.rub.nds.ssl.analyzer.vnl.gui;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class MessageListModel extends AbstractTableModel {
    private MessageListAppender appender;

    private enum Columns {
        DATE("Date"),
        LEVEL("LogLevel"),
        LOGGER("Logger (Class)"),
        MESSAGE("Message");

        final String name;
        private Columns(String name) {
            this.name = name;
        }
    }

    /**
     * @return The singleton Appender instance belonging to this MessageListModel
     */
    public AppenderSkeleton getAppender() {
        if(appender == null)
            appender = new MessageListAppender();

        return appender;
    }

    @Override
    public String getColumnName(int column) {
        if(0 > column || column >= Columns.values().length)
            return null;
        return Columns.values()[column].name;
    }

    @Override
    public int getRowCount() {
        return appender == null? 0 : appender.size();
    }

    @Override
    public int getColumnCount() {
        return Columns.values().length;
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
            case DATE:
                return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
                        .format(new Date(event.getTimeStamp()));
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
        }

        /** {@inheritDoc} */
        @Override
        protected void append(LoggingEvent loggingEvent) {
            events.add(loggingEvent);
            fireTableRowsInserted(events.size() -1, events.size() -1);
        }

        /** flushes the list, but does not set <code>closed</code> */
        @Override
        public void close() {
            final int oldSize = events.size();
            events.clear();
            fireTableDataChanged();
        }

        /** {@inheritDoc} */
        @Override
        public boolean requiresLayout() {
            return false;
        }

        public int size() {
            return events.size();
        }

        public LoggingEvent event(int index) throws IndexOutOfBoundsException {
            return events.get(index);
        }
    }
}
