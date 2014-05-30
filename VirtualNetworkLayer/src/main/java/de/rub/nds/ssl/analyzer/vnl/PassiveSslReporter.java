package de.rub.nds.ssl.analyzer.vnl;

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
        System.out.println("looping done");
	}
	
	public void run() {
        //open pcap on local live device
        Pcap pcap = Pcap.openLive();
        System.out.println("now looping over live capture");
        
        // Give control to pcap, pcap will use callbacks.
        pcap.loopAsynchronous(handler);
        
        System.out.println("looping done");
	}
	
	public void startMonitorThread() {
		Runnable t = new Runnable() {
			
			@Override
			public void run() {
				while(true) {
					handler.printStats();
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				
			}
		};
		(new Thread(t)).start();
	}

	/**
	 * @param args Optionally a pcap-file that will be used. If none is given,
	 * a live capture is started.
	 */
	public static void main(String[] args) {
		PassiveSslReporter psr = new PassiveSslReporter();
		psr.startMonitorThread();
		if (args.length == 0) {
			psr.run();
		} else {
			for (String string : args) {
				psr.run(string);
			}
		}
        psr.handler.printStats();
		System.exit(0);
	}

}
