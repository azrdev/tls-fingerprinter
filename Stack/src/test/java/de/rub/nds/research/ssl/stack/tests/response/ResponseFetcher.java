package de.rub.nds.research.ssl.stack.tests.response;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.sql.Timestamp;
import java.util.Observable;
import java.util.Observer;

import org.apache.log4j.Logger;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.ObservableBridge;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;
import de.rub.nds.research.timingsocket.TimingSocket;

/**
 * Fetches the responses from the socket.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 23, 2012
 */
public class ResponseFetcher implements Observer{
	
    /**
     * Record header.
     */
    private byte[] header;
    /**
     * Handshake workflow.
     */
    private SSLHandshakeWorkflow workflow;
    /**
     * Network socket.
     */
	private Socket socket;
	/**
	 * Input stream of the socket.
	 */
	private InputStream in;
	/**
	 * Log4j logger.
	 */
	static Logger logger = Logger.getRootLogger();

	
	public ResponseFetcher(Socket so, SSLHandshakeWorkflow workflow) {
		this.workflow = workflow;
		//observe the DATA_SEND state
		this.workflow.addObserver(this, EStates.DATA_SEND);
		if (so != null){
			this.socket = so;
			try {
				this.in = so.getInputStream();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * Fetch the responses from the socket.
	 */
	@Override
	public void update(Observable o, Object arg) {
		EStates states = null;
		ObservableBridge obs;
		DataInputStream dis = new DataInputStream(in);
		if (o != null && o instanceof ObservableBridge) {
			obs = (ObservableBridge) o;
			states = (EStates) obs.getState();
		}
		if (states != null) {
			if (states == EStates.DATA_SEND) {
				int traceListSize = workflow.getTraceList().size();
				EStates currentState = workflow.getTraceList().get(traceListSize-1).getState();
				switch(currentState) {
				case CLIENT_HELLO:
					try {
						fetchNextHeader();
					} catch (IOException e1) {
						logger.info("### Connection reset by peer.");
						workflow.closeSocket();
						return;
					}
					while (workflow.getCurrentState() != EStates.SERVER_HELLO_DONE.getID()) {
						this.extractAndHashMessage();
						if (workflow.getCurrentState() != EStates.SERVER_HELLO_DONE.getID() &&
								workflow.getCurrentState() != EStates.ALERT.getID()) {
							try {
								fetchNextHeader();
							} catch (IOException e) {
								logger.info("### Connection reset by peer.");
								workflow.closeSocket();
								return;
							}
						}
						else if (workflow.getCurrentState() == EStates.ALERT.getID()) {
							logger.info("### Connection reset due to FATAL_ALERT.");
							workflow.closeSocket();
							return;
						}

					}
					break;
				case CLIENT_KEY_EXCHANGE:
					try {
						if(dis.available()>0) {
							fetchNextHeader();
							this.extractAndHashMessage();
							if (workflow.getCurrentState() == EStates.ALERT.getID()) {
								logger.info("### Connection reset due to FATAL_ALERT.");
								workflow.closeSocket();
								return;
							}
							else {
								logger.info("### Unexpected message !!!");
								workflow.closeSocket();
								return;
							}

						}
					} catch (IOException e) {
						logger.info("### Connection reset by peer.");
						workflow.closeSocket();
						return;
					}
					break;
				case CLIENT_CHANGE_CIPHER_SPEC:
					try {
						if(dis.available()>0) {
							fetchNextHeader();
							this.extractAndHashMessage();
							if (workflow.getCurrentState() == EStates.ALERT.getID()) {
								logger.info("### Connection reset due to FATAL_ALERT.");
								workflow.closeSocket();
								return;
							}
							else {
								logger.info("### Unexpected message !!!");
								workflow.closeSocket();
								return;
							}

						}
					} catch (IOException e) {
						logger.info("### Connection reset by peer.");
						workflow.closeSocket();
						return;
					}
					break;
				case CLIENT_FINISHED:
					try {
						fetchNextHeader();
					} catch (IOException e) {
						logger.info("### Connection reset by peer.");
						workflow.closeSocket();
						return;
					}
					while (workflow.getCurrentState() != EStates.SERVER_FINISHED.getID()) {
						this.extractAndHashMessage();
						if (workflow.getCurrentState() != EStates.SERVER_FINISHED.getID() &&
								workflow.getCurrentState() != EStates.ALERT.getID()) {
							try {
								fetchNextHeader();
							} catch (IOException e) {
								logger.info("### Connection reset by peer.");
								workflow.closeSocket();
								return;
							}
						}
						else if (workflow.getCurrentState() == EStates.ALERT.getID()) {
							logger.info("### Connection reset due to FATAL_ALERT.");
							workflow.closeSocket();
							return;
						}
					}
					break;
				default:
					break;
				}
			}	
		}
	}
	
	/**
	 * Decode the response and update the hash value.
	 */
	private void extractAndHashMessage() {
		Trace trace = null;
		byte [] recordBytes = this.getRecordBytes();
		trace = new Trace();
		//set the Timestamp and exact time of message arrival
		trace.setTimestamp(new Timestamp(System.currentTimeMillis()));
		trace.setNanoTime(System.nanoTime());

		if (this.workflow.isTimingEnabled() && this.workflow.isWaitingForTime()) {
			workflow.setWaitingForTime(false);
			trace.setAccurateTime(((TimingSocket) socket).getTiming());
		}
		SSLResponse response = new SSLResponse(recordBytes, workflow);
		response.handleResponse(trace, recordBytes);
		//hash current record
		workflow.updateHash(workflow.getHashBuilder(), recordBytes);
	}
	
	/**
	 * Get the bytes of the complete response record.
	 * @return Record bytes
	 */
	private byte [] getRecordBytes() {
		//get the record header of the message
		byte [] header = this.getRecordHeader();
		//Determine the length of the frame
		int length = (header[3] & 0xff) << 8 | (header[4] & 0xff);
		byte[] answer = new byte[length + header.length];
		System.arraycopy(header, 0, answer, 0, header.length);
		try {
			in.read(answer, header.length, length);
		} catch (SocketException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			logger.info("### Connection reset by peer.");
			workflow.closeSocket();
		}
		return answer;
	}
	
	/**
	 * Fetch the record header bytes of the response.
	 * @throws IOException Is thrown when no bytes are available.
	 */
	private void fetchNextHeader() throws IOException {
		byte[] header = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED];
		int readBytes = 0;
				readBytes = in.read(header);
				if (readBytes == -1) {
					logger.info("### Connection reset by peer.");
					throw new IOException();
				}
		this.setRecordHeader(header);
	}
	
	/**
	 * Set the record header of the message.
	 * @param header Record header
	 */
	private void setRecordHeader(byte [] header) {
		byte [] tmp = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED];
		if(header != null) {
			System.arraycopy(header, 0, tmp, 0, ARecordFrame.LENGTH_MINIMUM_ENCODED);
		}
		this.header = tmp;
	}
	
	/**
	 * Get the record header of the message.
	 * @return Record header
	 */
	private byte [] getRecordHeader() {
		byte [] tmp = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED];
		System.arraycopy(header, 0, tmp, 0, ARecordFrame.LENGTH_MINIMUM_ENCODED);
		return tmp;
	}

}
