package de.rub.nds.ssl.attacker.misc;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Scanner;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public final class CommandLineWorkflowExecutor {

    /**
     * Command.
     */
    private String command;
    /**
     * Ticks (execution duration of the request).
     */
    private long ticks;

    /**
     * Instance of this executor.
     *
     * @param command The command to be executed.
     */
    public CommandLineWorkflowExecutor(final String command) {
        this.command = command + " ";
    }

    /**
     * This function first encodes Base64 the input msg. Then, it takes the
     * prßepared command line statement, appends Base64 encoded msg, and
     * executes the command.
     *
     * @param msg PKCS1 encrypted message
     * @return Number of ticks
     * @throws OracleException
     */
    public long executeClientWithPMS(final byte[] msg) throws OracleException {
        String base64msg = new String(Base64.encode(msg));
        String cmd = command + base64msg;
        Runtime rt = Runtime.getRuntime();
        try {
            Process proc = rt.exec(cmd);
            // error fetcher
            CommandLineFetcher error = new CommandLineFetcher(proc.
                    getErrorStream());

            // output fetcher
            CommandLineFetcher output = new CommandLineFetcher(proc.
                    getInputStream());

            error.start();
            output.start();

            int exitVal = proc.waitFor();

            // we have to wait until the output thread reads the complete lines
            output.join();
            if (exitVal != 0) {
                throw new OracleException("Exit value incorrect:\n" + output.sb 
                        + "\n" + error.sb, error.e);
            }

            if (error.e != null) {
                throw new OracleException("Error Fetcher Exception:\n" + 
                        output.sb + "\n" + error.sb, error.e);
            }

            if (output.e != null) {
                throw new OracleException("Output Fetcher Exception\n" + 
                        output.sb + "\n" + error.sb, output.e);
            }
            //System.out.println("there are your ticks: " + output.ticks);

            return output.ticks;

        } catch (IOException ioe) {
            throw new OracleException(ioe.getLocalizedMessage(), ioe);
        } catch (InterruptedException ie) {
            throw new OracleException(ie.getLocalizedMessage(), ie);
        }
    }

    /**
     * Getter for ticks.
     * @return Ticks.
     */
    public long getTicks() {
        return ticks;
    }

    private class CommandLineFetcher extends Thread {

        /**
         * Indicates that the next sent message is PMS and we should read ticks.
         */
        private final static String PMS_INFO = "PMS is now encrypted";
        /**
         * The line containing this string contains the number of ticks.
         */
        private final static String TICKS_INFO = "We were receiving info after";
        /**
         * Input stream from the command line.
         */
        private InputStream is;
        /**
         * String builder.
         */
        StringBuilder sb;
        /**
         * Exception found during processing.
         */
        Exception e;
        /**
         * Resulting number of ticks.
         */
        private long ticks;
        /**
         * Indicates that we should now read ticks.
         */
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
//                    System.out.println(line);

                    // indicates that the next ticks are relevant for us
                    if (line.contains(PMS_INFO)) {
                        readTicks = true;
                    }

                    // reading the relevant ticks
                    if (readTicks && line.contains(TICKS_INFO)) {
                        Scanner sc = new Scanner(line);
                        sc.useDelimiter("[^0-9]+");
                        if (sc.hasNextLong()) {
                            ticks = sc.nextLong();
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

}
