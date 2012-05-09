package de.rub.nds.research.ssl.stack.tests.trace;

import java.util.Date;

/**
 * Trace for protocol processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de Apr 17, 2012
 */
public abstract class ATrace {

    /**
     * Timestamp im milliseconds.
     */
    private Date timestamp = null;
    /**
     * Time in nano-precesion.
     */
    private Long nanoTime = null;

    /**
     * Public constructor for the trace which sets the current. timestamp and
     * time in nano-precision.
     */
    public ATrace() {
        this.timestamp = new Date(System.currentTimeMillis());
        this.nanoTime = System.nanoTime();
    }

    /**
     * Get the timestamp of the trace.
     *
     * @return Timestamp
     */
    public final Date getTimestamp() {
        return timestamp;
    }

    /**
     * Set the timestamp of the trace.
     *
     * @param timestamp Timestamp
     */
    public final void setTimestamp(final Date timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Get the time in nano-precision.
     *
     * @return Time in nano-precision
     */
    public final Long getNanoTime() {
        return this.nanoTime;
    }

    /**
     * Set the time in nano-precision.
     *
     * @param nanoTime Time in nano-precision
     */
    public final void setNanoTime(final Long nanoTime) {
        this.nanoTime = nanoTime;
    }
}
