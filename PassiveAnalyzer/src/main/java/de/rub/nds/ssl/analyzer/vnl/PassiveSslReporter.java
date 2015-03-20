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
import net.sourceforge.argparse4j.internal.HelpScreenException;
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
                        handler.printStats(false);
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
                handler.printStats(true);
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

        ArgumentParser argParser = ArgumentParsers
                .newArgumentParser("TLS Fingerprinter")
                .defaultHelp(true);
        argParser.addArgument("--open-live", "-l").action(storeTrue())
                .help("Open a live capture after processing all input files" +
                      " (and possibly stdin).");
        argParser.addArgument("--open-stdin", "-s").action(storeTrue())
                .help("Open standard input as capture, after processing all input files.\n" +
                      "Use i.e. with dumpcap -w - | java ... -s");
        argParser.addArgument("--graphical", "-g").action(storeTrue()).help("Start GUI");

        argParser.addArgument("--display-messages").dest("display_messages")
                .nargs("?").type(Boolean.class).setDefault(true).metavar("bool")
                .help("Show \"changed alert\" popup messages on the tray icon. " +
                        "Only has an effect if --graphical enabled");
        argParser.addArgument("--save-fingerprints").dest("save_fingerprints")
                .nargs("?").type(Boolean.class).setDefault(false).metavar("bool")
                .help("Store fingerprints to ~/.ssl-reporter/");
        argParser.addArgument("--save-captures").dest("save_captures")
                .action(storeTrue())
                .help("Write .pcap dumps of handshakes to ~/.ssl-reporter/captures/");
        argParser.addArgument("--resumption-guessing").dest("resumption_guessing")
                .nargs("?").type(Boolean.class).setDefault(true).metavar("bool")
                .help("Guess Session Resumption fingerprints.");
        argParser.addArgument("inputFile").nargs("*").help("Input .pcap files to read");

        Namespace _parsedArgs = null;
        try {
            _parsedArgs = argParser.parseArgs(args);
        } catch (HelpScreenException e) {
            argParser.handleError(e);
            System.exit(0);
        } catch (ArgumentParserException e) {
            argParser.handleError(e);
            logger.error(e);
            System.exit(1);
        }
        final Namespace parsedArgs = _parsedArgs;

        if(parsedArgs.getList("inputFile").isEmpty() &&
                !parsedArgs.getBoolean("open_stdin") &&
                !parsedArgs.getBoolean("open_live")) {
            System.out.println(
                    "No pcap input specified. The application will only process the " +
                    "stored data (saved fingerprints, statistics) and then exit, or " +
                    "show them in the GUI.\nUse --help for usage instructions.");
        }

        final PassiveSslReporter psr = new PassiveSslReporter();
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                psr.handler.saveStatistics();
            }
        }));
        psr.handler.setFingerprintReporting(true,
                parsedArgs.getBoolean("save_fingerprints"),
                parsedArgs.getBoolean("save_captures"),
                parsedArgs.getBoolean("resumption_guessing"));

        if(parsedArgs.getBoolean("graphical")) {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (ClassNotFoundException |
                    IllegalAccessException |
                    InstantiationException |
                    UnsupportedLookAndFeelException e) {
                logger.debug("Could not set System LAF: " + e, e);
            }
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    @Override
                    public void run() {
                        final MainWindow window = new MainWindow(
                                psr.handler.getFingerprintListener(),
                                psr.handler.getFingerprintStatistics());
                        window.setShowMessages(parsedArgs.getBoolean("display_messages"));
                    }
                });
            } catch (InterruptedException e) {
                logger.debug("Could not start GUI: " + e, e);
            } catch (InvocationTargetException e) {
                logger.warn("Could not start GUI: " + e, e);
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
