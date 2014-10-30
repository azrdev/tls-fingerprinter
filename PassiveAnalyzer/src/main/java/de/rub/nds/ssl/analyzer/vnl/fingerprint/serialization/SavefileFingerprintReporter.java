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
    private PrintWriter newFpWriter;
    private PrintWriter changedFpWriter;

    /**
     * Ctor for an instance saving new and changed fingerprints to one file
     */
    public SavefileFingerprintReporter(Path saveFile) throws IOException {
        logger.debug("saving to " + saveFile);
        Files.createDirectories(saveFile.getParent());
        newFpWriter = new PrintWriter(Files.newBufferedWriter(saveFile,
                Charset.forName("UTF8"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND), true);

        changedFpWriter = newFpWriter;

        newFpWriter.println("# " + new Date());
    }

    /**
     * Ctor for an instance saving new and changed fingerprints, to different files
     * @throws IOException If any file could not be opened for appending
     */
    public SavefileFingerprintReporter(Path saveFileNew, Path saveFileChanged)
            throws IOException {
        logger.debug("saving new fingerprints to " + saveFileNew);
        Files.createDirectories(saveFileNew.getParent());
        newFpWriter = new PrintWriter(Files.newBufferedWriter(saveFileNew,
                Charset.forName("UTF8"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND), true);
        newFpWriter.println("# " + new Date());

        logger.debug("saving changed fingerprints to " + saveFileChanged);
        Files.createDirectories(saveFileChanged.getParent());
        changedFpWriter = new PrintWriter(Files.newBufferedWriter(saveFileChanged,
                Charset.forName("UTF8"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND), true);
        changedFpWriter.println("# " + new Date());
    }

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             List<TLSFingerprint> previousFingerprints) {
        changedFpWriter.println(Serializer.serialize(sessionIdentifier, fingerprint));
    }

    @Override
    public void reportUpdate(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint) {
        //nothing
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier,
                          TLSFingerprint tlsFingerprint) {
        newFpWriter.println(Serializer.serialize(sessionIdentifier, tlsFingerprint));
    }

    @Override
    protected void finalize() throws Throwable {
        newFpWriter.close();
        super.finalize();
    }
}
