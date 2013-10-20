package de.rub.nds.ssl.stack.trace;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;

/**
 * MessageContainer information about the handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.1 Apr 10, 2012
 */
public final class MessageContainer {

    /**
     * Newly constructed record.
     */
    private ARecordFrame currentRecord = null;
    /**
     * Newly encoded bytes to send *
     */
    private byte[] currentRecordBytes = null;
    /**
     * Original record before manipulation.
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
     * Timestamp.
     */
    private long timestamp;
    /**
     * Previous state.
     */
    private EStates previousState;

    /**
     * Empty constructor.
     */
    public MessageContainer() {
        this.timestamp = System.nanoTime();
    }

    /**
     * Public constructor of a MessageContainer object.
     *
     * @param record Record frame
     * @param timestamp Timestamp
     */
    public MessageContainer(final ARecordFrame record, final long timestamp) {
        this.setCurrentRecord(record);
        this.setTimestamp(timestamp);
    }

    /**
     * Public constructor of a MessageContainer object.
     *
     * @param bytes Record bytes
     * @param timestamp Timestamp
     */
    public MessageContainer(final byte[] bytes, final long timestamp) {
        this.setCurrentRecordBytes(bytes);
        this.setTimestamp(timestamp);
    }

    /**
     * Public constructor of a MessageContainer object.
     *
     * @param state State of the stack
     * @param currentRecord Newly constructed record
     * @param oldRecord Original record before manipulation
     * @param isContinued Handshake enumeration was used for this record
     */
    public MessageContainer(EStates state, final ARecordFrame currentRecord,
            final ARecordFrame oldRecord, final boolean isContinued) {
        this.setState(state);
        this.setCurrentRecord(currentRecord);
        this.setOldRecord(oldRecord);
        this.setContinued(isContinued);
    }

    /**
     * Public constructor of a MessageContainer object.
     *
     * @param state State of the stack
     * @param currentRecord Newly constructed record
     * @param oldRecord Original record before manipulation
     * @param isContinued Handshake enumeration was used for this record
     * @param timestamp Timestamp
     */
    public MessageContainer(EStates state, final ARecordFrame currentRecord,
            final ARecordFrame oldRecord, final boolean isContinued,
            final Long timestamp) {
        this.setState(state);
        this.setCurrentRecord(currentRecord);
        this.setOldRecord(oldRecord);
        this.setContinued(isContinued);
        this.setTimestamp(timestamp);
    }

    /**
     * Get the current state.
     *
     * @return Current state.
     */
    public EStates getState() {
        return this.state;
    }

    /**
     * Set the current state.
     *
     * @param state Current state.
     */
    public void setState(EStates state) {
        this.state = state;
    }

    /**
     * Get the previous state.
     *
     * @return Previous state.
     */
    public EStates getPreviousState() {
        return this.previousState;
    }

    /**
     * Set the previous state.
     *
     * @param state Previous state.
     */
    public void setPreviousState(EStates state) {
        this.previousState = state;
    }

    /**
     * Get the current record.
     *
     * @return Current record
     */
    public ARecordFrame getCurrentRecord() {
        return currentRecord;
    }

    /**
     * Set the current  record.
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
     * Get original record before manipulation.
     *
     * @return Old record
     */
    public ARecordFrame getOldRecord() {
        return oldRecord;
    }

    /**
     * Set original record before manipulation.
     *
     * @param oldRecord Old record
     */
    public void setOldRecord(final ARecordFrame oldRecord) {
        this.oldRecord = oldRecord;
    }

    /**
     * Does this message belong to a multi message record.
     *
     * @return true if handshake enumeration was used for this record
     */
    public boolean isContinued() {
        return isContinued;
    }

    /**
     * Set if this message belongs to a multi message record.
     *
     * @param isContinued true if handshake enumeration was used for this record
     * / false if not
     */
    public void setContinued(final boolean isContinued) {
        this.isContinued = isContinued;
    }

    /**
     * Get the timestamp.
     *
     * @return Timestmap
     */
    public Long getTimestamp() {
        return this.timestamp;
    }

    /**
     * Set the timestamp.
     *
     * @param timestamp Time
     */
    public void setTimestamp(final Long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Prepares the message (sets the encoded representation).
     * Checks if the message was already encoded and if not encodes it.
     */
    public void prepare() {
        byte[] msg;
        if (getCurrentRecordBytes() == null) {
            msg = getCurrentRecord().encode(true);
            setCurrentRecordBytes(msg);
        }
    }
}
