package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * MessageContainer information about the SSL handshake processing.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @see de.rub.nds.ssl.stack.trace.MessageContainer
 */
//TODO: merge back / subclass stack.MessageContainer
public final class MessageContainer {
    private static Logger logger = Logger.getLogger(MessageContainer.class);

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
     * Associated Pcap packet.
     */
    private PcapPacket pcapPacket;
    /**
     * Previous state.
     */
    private EStates previousState;

    /**
     * Indices of the TLSPlaintext record(s) which contained bytes of our ARecordFrame.
     * Only set after decoding.
     */
    private List<Integer> fragmentSourceRecords = new LinkedList<>();

    /**
     * Indices of the TCP segment(s) which contained bytes of our TLSPlaintext record
     */
    private List<Integer> recordSourceSegments = new LinkedList<>();

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
     * @param packet PcapPacket which included the frame
     */
    public MessageContainer(final ARecordFrame record, final PcapPacket packet) {
        this.setCurrentRecord(record);
        this.setTimestamp(packet.getTimeStamp());
        this.setPcapPacket(packet);
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
     * Get the previous state in handshake.
     *
     * @return Previous state in handshake
     */
    public EStates getPreviousState() {
        return this.previousState;
    }

    /**
     * Set the previous state.
     *
     * @param state Previous state in handshake.
     */
    public void setPreviousState(EStates state) {
        this.previousState = state;
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
     * Get the associated Pcap packet, if available.
     *
     * @return Pcap packet
     */
    public PcapPacket getPcapPacket() {
        return pcapPacket;
    }

    /**
     * Set the associated Pcap packet.
     *
     * @param packet Pcap packet
     */
    public void setPcapPacket(final PcapPacket packet) {
        this.pcapPacket = packet;
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
     * Set the time .
     *
     * @param timestamp Time
     */
    public void setTimestamp(final Long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Prepares the message. Checks if the message was already encoded and if
     * not encodes it.
     */
    public void prepare() {
        byte[] msg;
        if (getCurrentRecordBytes() == null) {
            msg = getCurrentRecord().encode(true);
            setCurrentRecordBytes(msg);
        }
    }

    /**
     * Only set after decoding.
     * @return The indices of the TLSPlaintext record(s) which contained bytes of our
     * ARecordFrame.
     */
    public List<Integer> getFragmentSourceRecords() {
        return new ArrayList<>(fragmentSourceRecords);
    }

    void addFragmentSourceRecord(Integer recordIndex) {
        //TODO: cannot decode split ARecordFrame, and MessageContainer doesn't know multiple packets attached to one ARecordFrame, either
        if(fragmentSourceRecords.size() > 0)
            logger.warn("more than one record source for ARecordFrame: not implemented!");

        fragmentSourceRecords.add(recordIndex);
    }

    /**
     * Only set after decoding
     * @return The indices of the TCP segment(s) which contained bytes of our
     * TLSPlaintext record
     */
    public List<Integer> getRecordSourceSegments() {
        return new ArrayList<>(recordSourceSegments);
    }

    void setRecordSourceSegments(List<Integer> segmentIndices) {
        Objects.requireNonNull(segmentIndices);
        recordSourceSegments = new ArrayList<>(segmentIndices);
    }
}
