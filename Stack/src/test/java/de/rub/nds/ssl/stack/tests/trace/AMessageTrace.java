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
     * Time in nano-precesion.
     */
    private long nanoTime = 0L;
   
    /**
     * Public constructor for the trace which sets the current. 
     */
    public AMessageTrace() {
        this.nanoTime = System.nanoTime();
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
