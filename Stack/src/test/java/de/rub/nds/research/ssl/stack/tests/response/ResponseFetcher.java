package de.rub.nds.research.ssl.stack.tests.response;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Observable;
import org.apache.log4j.Logger;

/**
 * Fetches the responses from the socket.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 23, 2012
 */
public class ResponseFetcher extends Observable implements Runnable {

	/**
	 * Socket.
	 */
	private Socket socket;
    /**
     * Input stream of the socket.
     */
    private InputStream in;
    /**
     * Handshake workflow.
     */
    private SSLHandshakeWorkflow handFlow;
    /**
     * Signalizes if further bytes should be fetched.
     */
    private boolean fetchBytes = true;
    //static Logger logger = Logger.getRootLogger();


    /**
     * Initialize the ResponseFetcher to get responses from the
     * socket and notify observer.
     * @param so
     * @param workflow
     */
    public ResponseFetcher(Socket so, SSLHandshakeWorkflow workflow) {
        this.handFlow = workflow;
        this.socket = so;
        //add the handshake workflow as observer
        this.addObserver(this.handFlow);
        if (so != null) {
            this.socket = so;
            try {
                this.in = this.socket.getInputStream();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    /**
     * Run the thread. Fetch bytes from the socket and notify the observer
     * when a complete record is present.
     */
	@Override
	public void run() {
		byte[] header = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED];
		DataInputStream dis = new DataInputStream(in);
		while (this.fetchBytes) {
			try {
				socket.setSoTimeout(10000);
				dis.readFully(header);
				//Determine the length of the frame
		        int length = (header[3] & 0xff) << 8 | (header[4] & 0xff);
		        byte[] answer = new byte[length + header.length];
		        System.arraycopy(header, 0, answer, 0, header.length);
		        dis.readFully(answer, header.length, length);
		        //set changed Flag and notify the observer
		        this.setChanged();
		        this.notifyObservers(answer);
		        handFlow.wakeUp();
			} catch (IOException e) {
				//cancel fetching bytes if e.g. Socket is not available
				stopFetching();
			}
		}
		
	}
	
	/**
	 * Stop fetching futher bytes from the Socket.
	 * Will terminate the thread!
	 */
	public void stopFetching() {
		this.fetchBytes = false;
	}
    
    
}
