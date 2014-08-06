package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import org.apache.log4j.Logger;

/**
 * Sample program, that will passively listen and report HTTPS connections.
 * 
 * @author erik
 *
 */
public class PassiveSslReporter {

    private Logger logger = Logger.getRootLogger();
	
	static {
		ConnectionHandler.registerP0fFile(P0fFile.Embedded);
	}
	
	// Our handler will report on all new packets
	private SslReportingConnectionHandler handler = new SslReportingConnectionHandler();
	
	public void run(String filename) {
		Pcap pcap = Pcap.openOffline(new File(filename));
        logger.info("now looping over file");
        pcap.loop(handler);
        logger.info("looping done");
	}
	
	public void run() {
        //open pcap on local live device
        Pcap pcap = Pcap.openLive();
        logger.info("now looping over live capture");
        
        // Give control to pcap, pcap will use callbacks.
        pcap.loopAsynchronous(handler);
        
        logger.info("looping done");
	}
	
	public Thread startMonitorThread() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        handler.printStats();
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
                handler.printStats();
            }
        });
        t.start();
        return t;
	}

	/**
	 * @param args Optionally a pcap-file that will be used. If none is given,
	 * a live capture is started.
	 */
	public static void main(String[] args) {
		PassiveSslReporter psr = new PassiveSslReporter();
        Thread monitorThread = psr.startMonitorThread();
		if (args.length == 0) {
			psr.run();
		} else {
			for (String string : args) {
				psr.run(string);
			}
		}
        monitorThread.interrupt();
		System.exit(0);
	}

}
