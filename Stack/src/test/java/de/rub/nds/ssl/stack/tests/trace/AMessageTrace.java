package de.rub.nds.ssl.stack.tests.trace;

import java.util.Date;

/**
 * Trace for protocol processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 17, 2012
 */
public abstract class AMessageTrace {

    /**
     * Timestamp im milliseconds.
     */
    private Date timestamp = null;
    /**
     * Time in nano-precesion.
     */
    private long nanoTime = 0L;
    /**
     * Time in VNL-precesion.
     */
    private long vnlTime = 0L;
   
    /**
     * Public constructor for the trace which sets the current. timestamp and
     * time in nano-precision.
     */
    public AMessageTrace() {
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
    
    /**
     * Get the time in VNL-precision.
     *
     * @return Time in vnl-precision
     */
    public final Long getVNLTime() {
        return this.vnlTime;
    }

    /**
     * Set the time in VNL-precision.
     *
     * @param vnlTim Time in vnl-precision
     */
    public final void setVNLTime(final Long vnlTime) {
        this.vnlTime = vnlTime;
    }
}
