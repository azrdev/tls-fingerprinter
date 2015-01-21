package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

import de.rub.nds.ssl.analyzer.vnl.gui.MainWindow;
import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.apache.log4j.Logger;

import javax.swing.*;

import static net.sourceforge.argparse4j.impl.Arguments.storeFalse;
import static net.sourceforge.argparse4j.impl.Arguments.storeTrue;

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
        handler.setPcap(pcap);
        Pcap.Status status = pcap.loop(handler);
        logger.info("looping done, returned " + status);
	}

	public Pcap.Status run() {
        logger.info("opening live device");
        //open pcap on local live device
        pcap = Pcap.openLive();
        logger.info("now looping over live capture");
        
        // Give control to pcap, pcap will use callbacks.
        handler.setPcap(pcap);
        Pcap.Status status = pcap.loop(handler);
        
        logger.info("looping done, returned " + status);
        return status;
	}

    public Pcap.Status runOnStdin() {
        pcap = Pcap.openOfflineStdin();
        logger.info("now looping over stdin");
        handler.setPcap(pcap);
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
        Namespace parsedArgs = null;
        ArgumentParser argParser = ArgumentParsers
                .newArgumentParser("TLS Fingerprinter")
                .defaultHelp(true)
                .epilog("At least one of --open-live, --open-stdin or inputFiles is needed.");
        argParser.addArgument("--open-live", "-l").action(storeTrue())
                .help("Open a live capture after processing all input files" +
                      " (and possibly stdin).");
        argParser.addArgument("--open-stdin", "-s").action(storeTrue())
                .help("Open standard input as capture, after processing all input files.\n" +
                      "Use i.e. with dumpcap -w - | java ... -s");
        argParser.addArgument("--graphical", "-g").action(storeTrue()).help("Start GUI");
        argParser.addArgument("--save-captures").action(storeTrue())
                .help("Write .pcap dumps of handshakes");
        argParser.addArgument("--guess-session-resumption").action(storeTrue())
                .help("Enable guessing of Session Resumption fingerprints.");
        argParser.addArgument("--no-save-fingerprints").action(storeFalse())
                .help("Do not store fingerprints to files in ~/.ssl-reporter");
        argParser.addArgument("inputFile").nargs("*").help("Input .pcap files to read");
        try {
            parsedArgs = argParser.parseArgs(args);
        } catch (ArgumentParserException e) {
            argParser.handleError(e);
            logger.error(e);
            System.exit(1);
        }

        if(parsedArgs.getList("inputFile").isEmpty() &&
                !parsedArgs.getBoolean("open_stdin") &&
                !parsedArgs.getBoolean("open_live")) {
            argParser.printHelp();
            System.exit(1);
        }

        final PassiveSslReporter psr = new PassiveSslReporter();
        psr.handler.setFingerprintReporting(true,
                parsedArgs.getBoolean("no_save_fingerprints"),
                parsedArgs.getBoolean("save_captures"),
                parsedArgs.getBoolean("guess_session_resumption"));

        if(parsedArgs.getBoolean("graphical")) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    @Override
                    public void run() {
                        new MainWindow(psr.handler.getFingerprintListener());
                    }
                });
            } catch (InterruptedException e) {
                logger.debug("Error starting GUI: " + e, e);
            } catch (InvocationTargetException e) {
                logger.warn("Error starting GUI: " + e, e);
            }
        }

        Thread monitorThread = psr.startMonitorThread();
        try {
            for (String string : (List<String>) parsedArgs.get("inputFile")) {
                try {
                    psr.run(string);
                } catch (IllegalArgumentException e) {
                    logger.error(e);
                }
            }
            if(parsedArgs.get("open_stdin")) {
                psr.runOnStdin();
            }
            if(parsedArgs.get("open_live")) {
                try {
                    psr.run();
                } catch (IllegalArgumentException e) {
                    logger.error(e);
                    throw e;
                }
            }
        } finally {
            monitorThread.interrupt();
        }
	}

}
