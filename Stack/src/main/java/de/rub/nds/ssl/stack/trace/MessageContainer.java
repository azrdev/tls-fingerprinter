package de.rub.nds.ssl.stack.trace;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;

/**
 * MessageContainer information about the SSL handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.1 Apr 10, 2012
 */
public final class MessageContainer {

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
     * Timestamp.
     */
    private long timestamp;
    /**
     * Pcap trace.
     */
    private PcapTrace pcapTrace;

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
     * @param state State of the SSL stack
     * @param currentRecord Newly constructed SSL record
     * @param oldRecord Original SSL record before manipulation
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
     * @param state State of the SSL stack
     * @param currentRecord Newly constructed SSL record
     * @param oldRecord Original SSL record before manipulation
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
     * Extracts a byte[] from a Pcap trace.
     *
     * @param trace Pcap trace including the bytes.
     * @return Bytes of the Pcap trace.
     */
    public static byte[] getBytesFromTrace(final PcapTrace trace) {
        int capacity = 0;
        for (PcapPacket packet : trace) {
            capacity += packet.getLength();
        }

        byte[] answerBytes = new byte[capacity];
        int pointer = 0;
        for (PcapPacket packet : trace) {
            System.arraycopy(packet.getContent(), 0, answerBytes, pointer,
                    packet.getLength());
            pointer += packet.getLength();
        }

        return answerBytes;
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
     * Get the packet trace, if available.
     *
     * @return Packet trace
     */
    public PcapTrace getPcapTrace() {
        return pcapTrace;
    }

    /**
     * Set the packet trace.
     *
     * @param trace Packet trace
     */
    public void setPcapTrace(final PcapTrace trace) {
        this.pcapTrace = trace;
    }

    /**
     * Get the timestamp.
     *
     * @return Timestmap
     */
    public final Long getTimestamp() {
        return this.timestamp;
    }

    /**
     * Set the time .
     *
     * @param nanoTime Time
     */
    public final void setTimestamp(final Long timestamp) {
        this.timestamp = timestamp;
    }
}
