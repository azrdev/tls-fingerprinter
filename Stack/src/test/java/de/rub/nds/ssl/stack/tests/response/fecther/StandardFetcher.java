package de.rub.nds.ssl.stack.tests.response.fecther;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.tests.workflows.AWorkflow;
import de.rub.nds.ssl.stack.tests.workflows.TLS10HandshakeWorkflow;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Observable;

/**
 * Fetches the responses from the socket.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 23, 2012
 */
public class StandardFetcher extends AResponseFetcher {

    /**
     * Socket.
     */
    private Socket socket;
    /**
     * Input stream of the socket.
     */
    private InputStream in;
    
    /**
     * Signalizes if further bytes should be fetched.
     */
    private boolean fetchBytes = true;
    //static Logger logger = Logger.getRootLogger();

    /**
     * Initialize the StandardFetcher to get responses from the socket and
     * notify observer.
     *
     * @param so
     * @param workflow
     */
    public StandardFetcher(Socket so, AWorkflow workflow) {
        super(workflow);
        this.socket = so;
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
     * Run the thread. Fetch bytes from the socket and notify the observer when
     * a complete record is present.
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
                workflow.wakeUp();
            } catch (IOException e) {
                //cancel fetching bytes if e.g. Socket is not available
                stopFetching();
            }
        }

    }

    /**
     * Stop fetching futher bytes from the Socket. Will terminate the thread!
     */
    public void stopFetching() {
        this.fetchBytes = false;
    }
}
