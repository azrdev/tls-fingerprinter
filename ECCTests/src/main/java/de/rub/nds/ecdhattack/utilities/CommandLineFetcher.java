package de.rub.nds.ecdhattack.utilities;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class CommandLineFetcher extends Thread {

    private final static String QX_INFO = "==> Qx = ";
    private final static String QY_INFO = "==> Qy = ";
    /**
     * Input stream from the command line.
     */
    InputStream is;
    /**
     * Exception found during processing.
     */
    Exception e;
    /**
     * Result is a nasty point.
     */
    NastyPoint result = new NastyPoint();

    /**
     * Constructor
     *
     * @param is command line input stream
     */
    CommandLineFetcher(final InputStream is) {
        this.is = is;
    }

    public void run() {
        try (InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);) {
            String line = null;

            while ((line = br.readLine()) != null) {
                System.out.println(" > " + line);

                if (line.contains(QX_INFO)) {
                    result.x = new BigInteger(
                            line.substring(QX_INFO.length()));
                }
                if (line.contains(QY_INFO)) {
                    result.y = new BigInteger(
                            line.substring(QY_INFO.length()));
                }

                if (result.x != null && result.y != null) {
                    // we're done!
                    break;
                }
            }
        } catch (IOException ioe) {
            e = ioe;
        }
    }
}
