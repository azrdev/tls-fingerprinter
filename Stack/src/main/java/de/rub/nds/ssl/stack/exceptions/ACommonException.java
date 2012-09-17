package de.rub.nds.ssl.stack.exceptions;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.apache.log4j.lf5.LogLevel;

/**
 * Abstract prototype of common exceptions.
 * Implements commonly used routines or prototypes them.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * 04.01.2011
 */
public abstract class ACommonException extends Exception {
    /**
     * The message describing the exception.
     */
    private String message;
    /**
     *  A wrapped exception if this exception wraps a prior one.
     */
    private Exception wrappedException = null;
    /**
     * The log level if the exception should be automatically logged.
     */
    private LogLevel logLevel;

    /**
     * Constructor for a new, wrapped/unwrapped exception.
     *
     * @param exceptionMessage  Reason for this exception or <code>null</code>
     *                          if the default message should be used.
     * @param exceptionToWrap   Wrapped exception which caused the problem, if
     *                          any or <code>null</code> if there is no
     *                          exception to wrap.
     * @param exceptionLogLevel Log level for the generated message or
     *                          <code>null</code> if this issue should not be
     *                          logged.
     */
    protected ACommonException(final String exceptionMessage,
            final Exception exceptionToWrap, final LogLevel exceptionLogLevel) {
        //super(exceptionMessage);
        super(exceptionMessage, exceptionToWrap); //using the cause-mechanism

        this.setMessage(exceptionMessage);
        this.setLogLevel(exceptionLogLevel);

        if (exceptionToWrap == null) {
            this.setStackTrace(Thread.currentThread().getStackTrace());
        } else {
            this.setWrappedException(exceptionToWrap);
            this.setStackTrace(exceptionToWrap.getStackTrace());
        }

        // go ahead and log this exception!
        if (exceptionMessage != null && exceptionLogLevel != null) {
            Logger.getRootLogger().debug(exceptionMessage, exceptionToWrap);
        }

    }

    /**
     * Getter for exception message.
     *
     * @return Associated message
     */
    @Override
    public final String getMessage() {
        return this.message;
    }

    /**
     * Getter for wrapped exception.
     *
     * @return Wrapped excpeption
     */
    public final Exception getWrappedException() {
        return this.wrappedException;
    }

    /**
     * Getter for exception log level.
     *
     * @return Associated log level
     */
    public final LogLevel getLogLevel() {
        return this.logLevel;
    }

    /**
     * Setter for the exception message.
     *
     * @param exceptionMessage Exception message to be set
     */
    protected final void setMessage(final String exceptionMessage) {
        this.message = exceptionMessage;
    }

    /**
     * Setter for the wrapped Exception.
     *
     * @param exceptionToWrap The exception to be wrapped.
     */
    protected final void setWrappedException(final Exception exceptionToWrap) {
        this.wrappedException = exceptionToWrap;
    }

    /**
     * Setter for log level.
     *
     * @param exceptionLogLevel Log level to be set
     */
    protected final void setLogLevel(final LogLevel exceptionLogLevel) {
        this.logLevel = exceptionLogLevel;
    }
}
