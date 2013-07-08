/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.misc;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Scanner;
import org.apache.log4j.Logger;
import org.apache.log4j.lf5.LogLevel;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CommandLineWorkflowExecutor {

    private String command;
    
    private long ticks;
    
    private Logger logger = Logger.getRootLogger();
    
    public CommandLineWorkflowExecutor(final String command) {
        this.command = command;
    }

    /**
     * This function first encodes Base64 the input msg. Then, it takes 
     * the prßepared command line statement, appends Base64 encoded msg, and 
     * executes the command. 
     * 
     * @param msg PKCS1 encrypted message
     * @return Number of ticks
     * @throws OracleException 
     */
    public long executeClientWithPMS(byte[] msg) throws OracleException {
        String base64msg = new String(Base64.encode(msg));
        String cmd = command + base64msg;
        Runtime rt = Runtime.getRuntime();
        try {
            Process proc = rt.exec(cmd);
            // error fetcher
            CommandLineFetcher error = new CommandLineFetcher(proc.getErrorStream());

            // output fetcher
            CommandLineFetcher output = new CommandLineFetcher(proc.getInputStream());

            error.start();
            output.start();

            int exitVal = proc.waitFor();
            
            // we have to wait until the output thread reads the complete 
            // lines
            output.join();
            if (exitVal != 0) {
                throw new OracleException("Exit value incorrect. ", null,
                        LogLevel.FATAL);
            }

            if (error.e != null) {
                throw new OracleException("Error Fetcher Exception. ", error.e,
                        LogLevel.FATAL);
            }

            if (output.e != null) {
                throw new OracleException("Output Fetcher Exception. ",
                        output.e, LogLevel.FATAL);
            }
            logger.debug("there are your ticks: " + output.ticks);

//            String out = output.sb.toString();
//            System.out.println(out);
            return output.ticks;

        } catch (IOException ioe) {
            throw new OracleException(ioe.getLocalizedMessage(), ioe,
                    LogLevel.FATAL);
        } catch (InterruptedException ie) {
            throw new OracleException(ie.getLocalizedMessage(), ie,
                    LogLevel.FATAL);
        }
    }
    
    public long getTicks() {
        return ticks;
    }

    class CommandLineFetcher extends Thread {

        /** indicates that the next sent message is PMS and we should read 
         * ticks */
        private final static String PMS_INFO = "PMS is now encrypted";
        /** The line containing this string contains the number of ticks */
        private final static String TICKS_INFO = "We were receiving info after";
        /** input stream from the command line */
        InputStream is;
        /** string builder */
        StringBuilder sb;
        /** exception found during processing */
        Exception e;
        /** resulting number of ticks */
        long ticks;
        /** indicates that we should now read ticks */
        boolean readTicks = false;

        /**
         * Constructor
         * 
         * @param is command line input stream
         */
        CommandLineFetcher(InputStream is) {
            this.is = is;
            this.sb = new StringBuilder();
        }

        public void run() {
            try {
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String line = null;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                    logger.debug(line);
                    
                    // indicates that the next ticks are relevant for us
                    if(line.contains(PMS_INFO)) {
                        readTicks = true;
                    }
                    
                    // reading the relevant ticks
                    if (readTicks && line.contains(TICKS_INFO)) {
                        Scanner sc = new Scanner(line);
                        sc.useDelimiter("[^0-9]+");
                        if (sc.hasNextLong()) {
                            ticks = sc.nextLong();
//                            System.out.println(ticks);
                            readTicks = false;
                        }
                    }
                }
                is.close();
            } catch (IOException ioe) {
                e = ioe;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        CommandLineWorkflowExecutor clo = new CommandLineWorkflowExecutor(
                "cat ticks_sample.txt");
        clo.executeClientWithPMS("".getBytes());
    }
}
