package de.rub.nds.research.ssl.stack.tests.trace;

import java.io.Serializable;
import java.sql.Timestamp;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;

/**
 * Trace information about the SSL handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 10, 2012
 */
public final class Trace extends ATrace implements Serializable {

    /**
     * Serial ID.
     */
    private static final long serialVersionUID = 1L;
    /**
     * Newly constructed SSL record.
     */
    private ARecordFrame currentRecord = null;
    /**
     * Newly encoded bytes to send *
     */
    private byte[] currentRecordBytes = null;
    /**
     * Original SSL record before manipulation.
     */
    private ARecordFrame oldRecord = null;
    /**
     * Handshake enumeration was used for this record.
     */
    private boolean isContinued = false;
    /**
     * Current state in handshake.
     */
    private EStates state;
    /**
     * Enable time measurement.
     */
    private boolean timeMeasurementEnabled = false;

    /**
     * Empty constructor.
     */
    public Trace() {
    }

    /**
     * Public constructor of a Trace object.
     *
     * @param currentRecord Newly constructed SSL record
     * @param oldRecord Original SSL record before manipulation
     * @param isContinued Handshake enumeration was used for this record
     */
    public Trace(EStates state, final ARecordFrame currentRecord,
            ARecordFrame oldRecord,
            final boolean isContinued) {
        super();
        this.setState(state);
        this.setCurrentRecord(currentRecord);
        this.setOldRecord(oldRecord);
        this.setContinued(isContinued);
    }

    /**
     * Public constructor of a Trace object.
     *
     * @param currentRecord Newly constructed SSL record
     * @param timestamp Current sending/receiving timestamp of the message
     * @param oldRecord Original SSL record before manipulation
     * @param isContinued Handshake enumeration was used for this record
     * @param nanoTime Current time in nano precision
     */
    public Trace(EStates state, final ARecordFrame currentRecord,
            final Timestamp timestamp,
            final ARecordFrame oldRecord, boolean isContinued,
            final Long nanoTime) {
        this.setState(state);
        this.setCurrentRecord(currentRecord);
        this.setTimestamp(timestamp);
        this.setOldRecord(oldRecord);
        this.setContinued(isContinued);
        this.setNanoTime(nanoTime);
    }

    /**
     * Get the current state in handshake.
     *
     * @return Current state in handshake
     */
    public EStates getState() {
        return this.state;
    }

    /**
     * Set the current state.
     *
     * @param state Current state in handshake.
     */
    public void setState(EStates state) {
        this.state = state;
    }

    /**
     * Get the newly constructed SSL record.
     *
     * @return Current record
     */
    public ARecordFrame getCurrentRecord() {
        return currentRecord;
    }

    /**
     * Set the newly constructed SSL record.
     *
     * @param currentRecord Current record
     */
    public void setCurrentRecord(final ARecordFrame currentRecord) {
        this.currentRecord = currentRecord;
    }

    /**
     * Set current record bytes representation. May differ from currentRecord,
     * processor decides if currentRecord or currentRecord bytes are processed.
     *
     * @param currentBytes Current bytes representation.
     */
    public void setCurrentRecordBytes(byte[] currentBytes) {
        this.currentRecordBytes = currentBytes.clone();
    }

    /**
     * Get the current record bytes - if manually set. May differ from
     * currentRecord, processor decides if currentRecord or currentRecord bytes
     * are processed.
     *
     * @return Bytes of the current record if set, otherwise null.
     */
    public byte[] getCurrentRecordBytes() {
        byte[] result = null;
        if (this.currentRecordBytes != null) {
            result = this.currentRecordBytes.clone();
        }
        return result;
    }

    /**
     * Get original SSL record before manipulation.
     *
     * @return Old record
     */
    public ARecordFrame getOldRecord() {
        return oldRecord;
    }

    /**
     * Set original SSL record before manipulation.
     *
     * @param oldRecord Old record
     */
    public void setOldRecord(final ARecordFrame oldRecord) {
        this.oldRecord = oldRecord;
    }

    /**
     * Shows if handshake enumeration was used for present record.
     *
     * @return true if handshake enumeration was used for this record
     */
    public boolean isContinued() {
        return isContinued;
    }

    /**
     * Set present record as handshake enumerated message.
     *
     * @param isContinued true if handshake enumeration was used for this record
     * / false if not
     */
    public void setContinued(final boolean isContinued) {
        this.isContinued = isContinued;
    }

    /**
     * Enabled/Disable time measurement functionality for this trace.
     *
     * @param enabled True if time measurement should be enabled
     */
    public void setTimeMeasurementEnabled(boolean enabled) {
        this.timeMeasurementEnabled = enabled;
    }

    /**
     * Get time measurement enabled flag.
     *
     * @return True if time measurement is enabled for this trace.
     */
    public boolean isTimeMeasurementEnabled() {
        return this.isTimeMeasurementEnabled();
    }

    /**
     * Set the accurate timing as handled by the timing socket.
     *
     * @param timing Timing of this trace (Time interval between sending the
     * previous message and the reception of this message)
     */
    public void setAccurateTime(long timing) {
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
