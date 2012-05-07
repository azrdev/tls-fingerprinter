package de.rub.nds.research.ssl.stack.tests.trace;

import java.io.Serializable;
import java.sql.Timestamp;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.States;

/**Trace information about the SSL handshake processing.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Apr 10, 2012
 */
public class Trace extends ATrace implements Serializable {


	/**
	 * Serial ID.
	 */
	private static final long serialVersionUID = 1L;
	/** Newly constructed SSL record.*/
	private ARecordFrame currentRecord = null;
	/**Original SSL record before manipulation.*/ 
	private ARecordFrame oldRecord = null;
	/**Handshake enumeration was used for this record.*/
	private boolean isContinued = false;
	/**Current state in handshake.*/
	private States state;

	/**Empty constructor.*/
	public Trace() {
	}

	/** Public constructor of a Trace object.
	 * @param currentRecord Newly constructed SSL record
	 * @param oldRecord Original SSL record before manipulation
	 * @param isContinued Handshake enumeration was used for this record
	 */
	public Trace(States state, final ARecordFrame currentRecord, ARecordFrame oldRecord,
			final boolean isContinued) {
		super();
		this.setState(state);
		this.setCurrentRecord(currentRecord);
		this.setOldRecord(oldRecord);
		this.setContinued(isContinued);
	}

	/** Public constructor of a Trace object.
	 * @param currentRecord Newly constructed SSL record
	 * @param timestamp Current sending/receiving timestamp of the message
	 * @param oldRecord Original SSL record before manipulation
	 * @param isContinued Handshake enumeration was used for this record
	 * @param nanoTime Current time in nano precision
	 */
	public Trace(States state, final ARecordFrame currentRecord, final Timestamp timestamp,
		final ARecordFrame oldRecord, boolean isContinued, final Long nanoTime) {
		this.setState(state);
		this.setCurrentRecord(currentRecord);
		this.setTimestamp(timestamp);
		this.setOldRecord(oldRecord);
		this.setContinued(isContinued);
		this.setNanoTime(nanoTime);
	}

	/**
	 * Get the current state in handshake.
	 * @return Current state in handshake
	 */
	public States getState() {
		return this.state;
	}
	
	/**
	 * Set the current state.
	 * @param state Current state in handshake.
	 */
	public void setState(States state) {
		this.state = state;
	}

	/**Get the newly constructed SSL record.
	 * @return Current record
	 */
	public final ARecordFrame getCurrentRecord() {
		return currentRecord;
	}

	/**Set the newly constructed SSL record.
	 * @param currentRecord Current record
	 */
	public final void setCurrentRecord(final ARecordFrame currentRecord) {
		this.currentRecord = currentRecord;
	}

	/**Get original SSL record before manipulation.
	 * @return Old record
	 */
	public final ARecordFrame getOldRecord() {
		return oldRecord;
	}

	/**Set original SSL record before manipulation.
	 * @param oldRecord Old record
	 */
	public final void setOldRecord(final ARecordFrame oldRecord) {
		this.oldRecord = oldRecord;
	}

	/**Shows if handshake enumeration was used for present record.
	 * @return true if handshake enumeration was used for this record
	 */
	public final boolean isContinued() {
		return isContinued;
	}

	/**Set present record as handshake enumerated message.
	 * @param isContinued true if handshake enumeration
	 * was used for this record / false if not
	 */
	public final void setContinued(final boolean isContinued) {
		this.isContinued = isContinued;
	}

}
