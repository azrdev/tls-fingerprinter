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
    private static Logger logger = Logger.getRootLogger();
	
	static {
		ConnectionHandler.registerP0fFile(P0fFile.Embedded);
	}
	
	// Our handler will report on all new packets
	private SslReportingConnectionHandler handler = new SslReportingConnectionHandler();
    private Pcap pcap;

    private PassiveSslReporter() {
        logger.info("Starting up");
    }

	public void run(String filename) {
		pcap = Pcap.openOffline(new File(filename));
        logger.info("now looping over file " + filename);
        Pcap.Status status = pcap.loop(handler);
        logger.info("looping done, returned " + status);
	}

	public Pcap.Status run() {
        logger.info("opening live device");
        //open pcap on local live device
        pcap = Pcap.openLive();
        logger.info("now looping over live capture");
        
        // Give control to pcap, pcap will use callbacks.
        Pcap.Status status = pcap.loop(handler);
        
        logger.info("looping done, returned " + status);
        return status;
	}

    public Pcap.Status runOnStdin() {
        pcap = Pcap.openOfflineStdin();
        logger.info("now looping over stdin");
        Pcap.Status status = pcap.loop(handler);
        logger.info("looping done, returned " + status);
        return status;
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
        try {
            if (args.length == 0) {
                try {
                    psr.run();
                } catch(IllegalArgumentException e) {
                    logger.error(e);
                    throw e;
                }
            } else {
                for (String string : args) {
                    if(string.equals("-")) {
                        psr.runOnStdin();
                    } else
                        try {
                            psr.run(string);
                        } catch (IllegalArgumentException e) {
                            logger.error(e);
                        }
                }
            }
        } finally {
            monitorThread.interrupt();
        }
		System.exit(0);
	}

}
