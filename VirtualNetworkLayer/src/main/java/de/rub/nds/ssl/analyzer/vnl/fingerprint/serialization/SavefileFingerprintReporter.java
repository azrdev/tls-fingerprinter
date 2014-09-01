package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.List;

/**
 * Saves all reported fingerprints to a file, so they can be read back in by
 * FingerprintListener
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SavefileFingerprintReporter implements FingerprintReporter {
    private Logger logger = Logger.getLogger(getClass());
    private PrintWriter writer;

    public SavefileFingerprintReporter(Path saveFile) throws IOException {
        logger.debug("saving to " + saveFile);
        Files.createDirectories(saveFile.getParent());
        writer = new PrintWriter(Files.newBufferedWriter(saveFile,
                Charset.forName("UTF8"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND), true);

        writer.println("# " + new Date());
    }

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             List<TLSFingerprint> previousFingerprints) {
        saveFingerprint(sessionIdentifier, fingerprint);
    }

    @Override
    public void reportUpdate(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint) {
        //nothing
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier,
                          TLSFingerprint tlsFingerprint) {
        saveFingerprint(sessionIdentifier, tlsFingerprint);
    }

    private void saveFingerprint(SessionIdentifier sessionIdentifier,
                                 TLSFingerprint tlsFingerprint) {
        writer.println(Serializer.serialize(sessionIdentifier, tlsFingerprint));
    }

    @Override
    protected void finalize() throws Throwable {
        writer.close();
        super.finalize();
    }
}
