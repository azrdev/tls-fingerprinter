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
import java.util.Set;

/**
 * Saves all reported fingerprints to a file, so they can be read back in by
 * FingerprintListener
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SavefileFingerprintReporter implements FingerprintReporter {
    private static Logger logger = Logger.getLogger(SavefileFingerprintReporter.class);
    private PrintWriter newFpWriter;
    private PrintWriter changedFpWriter;
    private PrintWriter artificialFpWriter;

    /**
     * Ctor for an instance saving new, changed, and artificial fingerprints to one file
     */
    public SavefileFingerprintReporter(Path saveFile) throws IOException {
        logger.debug("saving to " + saveFile);
        artificialFpWriter = changedFpWriter = newFpWriter = open(saveFile);

        newFpWriter.println("# " + new Date());
    }

    /**
     * Ctor for an instance saving new, changed, and artificial fingerprints, to
     * different files. If any of the arguments is <code>null</code>, it is disabled.
     * @throws IOException If any (non-null) file could not be opened for appending
     */
    public SavefileFingerprintReporter(Path saveFileNew,
                                       Path saveFileChanged,
                                       Path saveFileArtificial) throws IOException {
        if(saveFileNew != null) {
            logger.debug("saving new fingerprints to " + saveFileNew);
            newFpWriter = open(saveFileNew);
            newFpWriter.println("# " + new Date());
        }

        if(saveFileChanged != null) {
            logger.debug("saving changed fingerprints to " + saveFileChanged);
            changedFpWriter = open(saveFileChanged);
            changedFpWriter.println("# " + new Date());
        }

        if(saveFileArtificial != null) {
            logger.debug("saving artificial fingerprints to " + saveFileArtificial);
            artificialFpWriter = open(saveFileArtificial);
            artificialFpWriter.println("# " + new Date());
        }
    }

    private static PrintWriter open(Path file) throws IOException {
        com.google.common.io.Files.createParentDirs(file.toFile());

        return new PrintWriter(Files.newBufferedWriter(
                file,
                Charset.forName("UTF8"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND),
                true);
    }

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             Set<TLSFingerprint> previousFingerprints) {
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
    public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        artificialFpWriter.println(Serializer.serialize(sessionIdentifier, fingerprint));
    }

    @Override
    protected void finalize() throws Throwable {
        newFpWriter.close();
        super.finalize();
    }
}
