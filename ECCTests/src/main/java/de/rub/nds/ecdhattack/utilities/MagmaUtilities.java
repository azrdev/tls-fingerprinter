package de.rub.nds.ecdhattack.utilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Magma Utilities.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Sep 20, 2013
 */
public class MagmaUtilities {
    private final String magmaLauncher;
    private final List<String> lines;

    public MagmaUtilities(final String magmaCodePath,
            final String magmaExecutablePath) throws IOException {
        magmaLauncher = magmaExecutablePath;

        File originalFile = new File(magmaCodePath);
        if (!originalFile.exists() || !originalFile.isFile() || !originalFile.
                canRead()) {
            throw new FileNotFoundException("File " + originalFile.getPath()
                    + " is either non-existent, not readble or no file at all.");
        } else {
            synchronized (this) {
                // read original code
                lines = Files.readAllLines(originalFile.toPath(),
                        StandardCharsets.UTF_8);
            }
        }
    }

    public synchronized NastyPoint getNewPoint(final String knownBits,
            final int yCounterStartValue)
            throws IOException, InterruptedException {
        NastyPoint result;
        Map<String, String> replaceMap = new HashMap<>(2);
        File modifiedFile;

        replaceMap.put("KnownBits :=", knownBits);
        int yCounter = yCounterStartValue - 1;
        do {
            yCounter++;
            replaceMap.put("changeme :=", yCounter + ";");
            modifiedFile = modifyCode(lines, replaceMap);

            // call Magma
            System.out.println("## MAGMA call with changeme := "
                    + yCounter);
            result = executeMagma(magmaLauncher, modifiedFile.toPath());
            System.out.println("## MAGMA terminated\n");

            // clean up
            Files.delete(modifiedFile.toPath());
        } while (result.x == null && result.y == null);
        result.yCounter = yCounter;

        return result;
    }

    private synchronized NastyPoint executeMagma(final String magmaCommand,
            final Path codePath)
            throws IOException, InterruptedException {
        String command = magmaCommand + " " + codePath.toString();
        Runtime runtime = Runtime.getRuntime();

        Process proc = runtime.exec(command);
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
            throw new IllegalStateException("Exit value incorrect", error.e);
        }

        if (error.e != null) {
            throw new IllegalStateException("Error Fetcher Exception", error.e);
        }

        if (output.e != null) {
            throw new IllegalStateException("Output Fetcher Exception", output.e);
        }

        return output.result;
    }

    private static synchronized File modifyCode(final List<String> lines, 
            final Map<String, String> replaceMap)
            throws IOException {
        // create tmp code
        for (String tmp : replaceMap.keySet()) {
            replaceValue(lines, tmp, replaceMap.get(tmp));
        }

        // write new code file
        return persistChanges(lines);
    }

    private static synchronized File persistChanges(final List<String> lines)
            throws IOException {
        File tmpFile = File.createTempFile("magma.code", null);
        // write
        try (FileWriter fileWriter = new FileWriter(tmpFile);) {
            for (String tmpLine : lines) {
                fileWriter.write(tmpLine);
                fileWriter.write(System.getProperty("line.separator"));
            }
        }

        return tmpFile;
    }

    private static void replaceValue(final List<String> lines,
            final String variable, final String newValue) {
        // replace
        boolean found = false;
        String tmp;
        for (int i = 0; i < lines.size(); i++) {
            if (found) {
                lines.set(i, newValue);
                break;
            }

            tmp = lines.get(i);
            if (tmp.contains(variable)) {
                found = true;
            }
        }
    }
}
