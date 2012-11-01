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
	
	public void run(String filename) {
		Pcap pcap = Pcap.openOffline(new File(filename));
        System.out.println("now looping over file");
        pcap.loop(handler);
	}
	
	public void run() {
        //open pcap on local live device
        Pcap pcap = Pcap.openLive();
        System.out.println("now looping over live capture");
        
        // Give control to pcap, pcap will use callbacks.
        pcap.loopAsynchronous(handler);
	}

	/**
	 * @param args Optinally a pcap-file that will be used. If none is given,
	 * a live capture is started.
	 */
	public static void main(String[] args) {
		PassiveSslReporter psr = new PassiveSslReporter();
		if (args.length == 0) {
			psr.run();
		} else {
			psr.run(args[0]);
		}

		System.exit(0);
	}

}
