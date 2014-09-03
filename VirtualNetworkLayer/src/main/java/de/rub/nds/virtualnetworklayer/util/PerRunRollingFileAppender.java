package de.rub.nds.virtualnetworklayer.util;

import org.apache.log4j.RollingFileAppender;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * RollingFileAppender that inserts the date and time of program execution start into the
 * logs filename, to obtain a different (rotated) logfile for each run.
 *
 * @see RollingFileAppender
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class PerRunRollingFileAppender extends RollingFileAppender {
    private static String datePrefix =
                new SimpleDateFormat("yyyy-MM-dd HH_mm_ss,SSS ").format(new Date());
    @Override
    public synchronized void setFile(String fileName, boolean append, boolean bufferedIO, int bufferSize) throws IOException {
        if(fileName.contains(datePrefix)) {
            super.setFile(fileName, append, bufferedIO, bufferSize);
        } else {
            Path path = Paths.get(fileName);
            Path pathWithDate = path.getParent().resolve(datePrefix + path.getFileName());
            super.setFile(pathWithDate.toString(), append, bufferedIO, bufferSize);
        }
    }
}
