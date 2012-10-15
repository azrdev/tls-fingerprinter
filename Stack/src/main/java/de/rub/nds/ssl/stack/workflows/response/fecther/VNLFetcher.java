package de.rub.nds.ssl.stack.workflows.response.fecther;

import de.rub.nds.ssl.stack.trace.Message;
import de.rub.nds.ssl.stack.workflows.AWorkflow;
import de.rub.nds.virtualnetworklayer.connection.pcap.FragmentSequence;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.socket.VNLSocket;
import java.util.List;

/**
 * Fetches the responses from the socket.
 *
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 * @version 0.1 Aug 30, 2012
 */
public class VNLFetcher extends AResponseFetcher {

    /**
     * Initialize the fetcher to get responses from the socket and notify the
     * observer.
     *
     * @param so Socket to work with
     * @param workflow Workflow to notify
     */
    public VNLFetcher(final VNLSocket so, final AWorkflow workflow) {
        super(so, workflow);
    }

    /**
     * Run the thread. Fetch bytes from the socket and notify the observer when
     * a complete record is present.
     */
    @Override
    public void run() {
        System.out.println("================> Started");
        PcapPacket packet = null;
        PcapConnection connection = ((VNLSocket) socket).getConnection();
        PcapTrace trace = connection.getTrace();
        List<FragmentSequence> sequences = trace.getFragmentSequences();
        Message response;
//        while (continueFetching()) {
//            try {
//System.out.println("===========> Fetching");
//                packet = connection.read(100);
//                trace = connection.getTrace();
//                sequences = trace.getFragmentSequences();
//System.out.println("===========> Elvis has left the building");
//                if(packet != null && !sequences.isEmpty() && sequences.get(0).isComplete()) {
//System.out.println("PACKET ARRIVED!"); 
//                    //set changed Flag and notify the observer
//                    this.setChanged();
//                    response = new Response(trace);
//                    this.notifyObservers(response);
//                    workflow.wakeUp();
//                } else {
//System.out.println("BOOLEAN packet " + (packet != null));
//System.out.println("BOOLEAN sequence " + sequences.isEmpty());
//System.out.println("BOOLEAN complete " + sequences.get(0).isComplete());
//                }
//            } catch(IOException e) {
//                //cancel fetching bytes if e.g. Socket is not available
//                stopFetching();
//            }
//        }
            try {
                while (sequences.isEmpty() | !sequences.get(0).isComplete()) {
System.out.println("LOOP DEAD");
                    synchronized (connection) {
                        connection.wait();
                    }
System.out.println("LOOP LOCKED");
                }
            } catch (InterruptedException e) {
                // TODO silently ignore
            }
            
//        }
    }
}
