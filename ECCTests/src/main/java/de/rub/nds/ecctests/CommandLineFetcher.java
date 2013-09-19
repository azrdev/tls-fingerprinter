package de.rub.nds.ecctests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class CommandLineFetcher extends Thread {

    private final static String QX_INFO = "==> Qx = ";
    private final static String QY_INFO = "==> Qy = ";
    /**
     * Input stream from the command line.
     */
    InputStream is;
    /**
     * String builder.
     */
    StringBuilder sb;
    /**
     * Exception found during processing.
     */
    Exception e;
    
    String result = null;

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
        try(InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);) {
            String line = null;
            
            int done = 0;
            while ((line = br.readLine()) != null) {
                    System.out.println(line);

                if (line.contains(QX_INFO)) {
                    sb.append(line.substring(QX_INFO.length()) + ",");
                    done++;
                }
                if (line.contains(QY_INFO)) {
                    sb.append(line.substring(QX_INFO.length()));
                    done++;
                }
                
                if(done == 2) {
                    result = sb.toString();
                    break;
                }
            }
        } catch (IOException ioe) {
            e = ioe;
        }
    }
}
