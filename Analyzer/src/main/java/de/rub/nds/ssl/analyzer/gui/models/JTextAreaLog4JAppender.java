package de.rub.nds.ssl.analyzer.gui.models;

import javax.swing.JTextArea;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Log4j appender - appends logs to a jTextArea.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 24, 2013
 */
public final class JTextAreaLog4JAppender extends AppenderSkeleton {

    /**
     * TextArea in which to output the logs.
     */
    private JTextArea textArea;

    /**
     * Public contructor - initializes the component.
     *
     * @param textArea Textarea to be suded for log output
     */
    public JTextAreaLog4JAppender(final JTextArea textArea) {
        // set teh appenders name
        this.name = getClass().getCanonicalName();
        this.textArea = textArea;
    }

    @Override
    public void close() {
        this.textArea = null;
    }

    @Override
    public boolean requiresLayout() {
        return false;
    }

    @Override
    protected void append(final LoggingEvent le) {
        textArea.append(le.getRenderedMessage());
        textArea.append("\n");
    }
}
