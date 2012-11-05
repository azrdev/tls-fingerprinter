package de.rub.nds.ssl.stack.workflows.response.fecther;

import de.rub.nds.research.timingsocket.TimingSocket;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.AWorkflow;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

/**
 * Fetches the responses from the socket.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 23, 2012
 */
public class TimingFetcher extends AResponseFetcher {
    //static Logger logger = Logger.getRootLogger();

    /**
     * Input stream of the socket.
     */
    protected InputStream in;
    
    /**
     * Initialize the fetcher to get responses from the socket and notify the
     * observer.
     *
     * @param so Socket to work with
     * @param workflow Workflow to notify
     */
    public TimingFetcher(final Socket so, final AWorkflow workflow) {
        super(so, workflow);
    }

    /**
     * Run the thread. Fetch bytes from the socket and notify the observer when
     * a complete record is present.
     */
    @Override
    public void run() {
        TimingSocket ts = (TimingSocket) this.socket;
        byte[] header = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED];
        try {
            this.in = ts.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        DataInputStream dis = new DataInputStream(in);
        MessageContainer response;
        while (continueFetching()) {
            try {
                ts.setSoTimeout(10000);
                dis.readFully(header);
                
                long time = ts.getTiming();
                
                System.out.println("TimingFetcher.run()" + time);
                
                //Determine the length of the frame
                int length = (header[3] & 0xff) << 8 | (header[4] & 0xff);
                byte[] answer = new byte[length + header.length];
                System.arraycopy(header, 0, answer, 0, header.length);
                dis.readFully(answer, header.length, length);
                
                //set changed Flag and notify the observer
                this.setChanged();
                response = new MessageContainer(answer, time);
                this.notifyObservers(response);
                workflow.wakeUp();
            } catch (IOException e) {
                e.printStackTrace();
                //cancel fetching bytes if e.g. Socket is not available
                stopFetching();
            }
        }

    }
}
