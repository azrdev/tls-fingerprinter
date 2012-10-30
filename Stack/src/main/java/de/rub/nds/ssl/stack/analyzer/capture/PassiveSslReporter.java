package de.rub.nds.ssl.stack.analyzer.capture;

import java.io.File;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

/**
 * Sample program, that will passively listen and report HTTPS connections.
 * 
 * @author erik
 *
 */
public class PassiveSslReporter {
	
	static {
		ConnectionHandler.registerP0fFile(P0fFile.Embedded);;
	}
	
	// Our handler will report on all new packets
	private SslReportingConnectionHandler handler = new SslReportingConnectionHandler();
	
	public PassiveSslReporter() {
		// Nothing to do here.
	}
	
	public void run() {

        //open pcap on local live device
        Pcap pcap = Pcap.openLive();
		//Pcap pcap = Pcap.openOffline(new File("/home/erik/ssl-retransmit.pcap"));
        System.out.println("now looping");
        
        // Give control to pcap, pcap will use callbacks.
        pcap.loopAsynchronous(handler);
        
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		PassiveSslReporter psr = new PassiveSslReporter();
		psr.run();

	}

}
