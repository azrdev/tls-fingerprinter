package de.rub.nds.ecctests;

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
 * ECC DH Attack Entry Point.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Sep 19, 2013
 */
public final class GetToThePoint {

    private static final String DEFAULT_CODE_PATH = "/opt/code.magma";
    private static final String MAGMA_COMMAND = "/home/chris/Desktop//MagmaLinux2.11/scripts/magma";

    /**
     * @param args the command line arguments
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void main(final String[] args) throws FileNotFoundException,
            IOException, InterruptedException {
        System.out.println(getNewPoint("<1,1,1,0>;"));
    }

    public static String getNewPoint(final String knownBits)
            throws IOException, InterruptedException {
        String result = null;
        Map<String, String> replaceMap = new HashMap<>(2);
        File originalFile = new File(DEFAULT_CODE_PATH);
        File modifiedFile;

        if (!originalFile.exists() || !originalFile.isFile() || !originalFile.
                canRead()) {
            throw new FileNotFoundException("File " + originalFile.getPath()
                    + " is either non-existent, not readble or no file at all.");
        } else {

            replaceMap.put("KnownBits :=", knownBits);
            int yCounter = 1;
            do {
                replaceMap.put("changeme :=", yCounter + ";");
                modifiedFile = modifyCode(originalFile, replaceMap);

                // call Magma
                result = executeMagma(modifiedFile.toPath());
                yCounter++;
            } while (result == null);

        }
        return result;
    }

    private static String executeMagma(final Path codePath) 
            throws IOException, InterruptedException {
        String command = MAGMA_COMMAND + " " + codePath.toString();
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
            throw new IllegalStateException("Exit value incorrect:\n"
                    + output.sb + "\n" + error.sb, error.e);
        }

        if (error.e != null) {
            throw new IllegalStateException("Error Fetcher Exception:\n"
                    + output.sb + "\n" + error.sb, error.e);
        }

        if (output.e != null) {
            throw new IllegalStateException("Output Fetcher Exception\n"
                    + output.sb + "\n" + error.sb, output.e);
        }

        return output.result;
    }

    private static File modifyCode(final File originalFile,
            final Map<String, String> replaceMap)
            throws IOException {
        // read
        List<String> lines = Files.readAllLines(originalFile.toPath(),
                StandardCharsets.UTF_8);

        // create tmp code
        for (String tmp : replaceMap.keySet()) {
            replaceValue(lines, tmp, replaceMap.get(tmp));
        }

        // write new code file
        return persistChanges(lines);
    }

    private static File persistChanges(final List<String> lines)
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
