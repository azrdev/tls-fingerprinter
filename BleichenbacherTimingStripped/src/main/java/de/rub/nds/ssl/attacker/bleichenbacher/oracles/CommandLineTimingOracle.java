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
public class CommandLineTimingOracle extends AOracle {

    /*
     * CONFIGURATION SECTION
     */
    /**
     * Amount of training measurementsTest.
     */
    private static final int TRAINING_AMOUNT = 1000;
    /**
     * Amount of warmup measurementsTest.
     */
    private static final int WARMUP_AMOUNT = 50;
    /**
     * Timing difference between invalid and valid timings.
     */
    private static final long VALID_INVALID_BOUNDARY = -20000;
    /**
     * Amount of measurementsTest per Oracle query.
     */
    private static final int MEASUREMENT_AMOUNT = 100;
    /**
     * TODO: Sebastian - bitte bitte bitte Parameter kommentieren!
     */
    private static final int MEASUREMENT_FACTOR_FOR_VALIDITY = 1;
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
     * RSA private key (needed for the cheat operation).
     */
    private RSAPrivateKey privateKey;
    /**
     * Cipher (needed for the cheat operation).
     */
    private Cipher cipher;

    /**
     * Create a new instance of this object.
     *
     * @param type
     * @param publicKey
     * @param privateKey
     */
    public CommandLineTimingOracle(final OracleType type,
            final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.oracleType = type;
        this.blockSize = Utility.computeBlockSize(publicKey);
        try {
            this.cipher = Cipher.getInstance("RSA/None/NoPadding");
            this.cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            ex.printStackTrace();
        }

        this.clwe = new CommandLineWorkflowExecutor("./client ");
    }

    /**
     * This method performs the statistical analysis of the timing
     * measurementsTest. It assumes that a valid key has a significantly lower
     * response time than an invalid key. In a nutshell, the method performs
     * Crosby's box test.
     *
     * @param testPKCS PKCS to be tested for validity.
     * @return True if the PKCS was a valid one or false otherwise.
     */
    private boolean isValidPKCS(final byte[] testPKCS) {
        boolean result = false;

        // TODO: Sebastian - hier muss der Code rein der valid von invalid 
        // unterscheidet.

        return result;
    }

    /**
     * Train the timing oracle.
     *
     * @param validPMS Valid PMS
     * @param invalidPMS InvalidPMS
     * @throws OracleException
     */
    public void trainOracle(final byte[] validPMS, final byte[] invalidPMS)
            throws OracleException {
        clwe.executeClientWithPMS(validPMS);
        clwe.executeClientWithPMS(invalidPMS);

        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < WARMUP_AMOUNT / 2; i++) {
            clwe.executeClientWithPMS(validPMS);
            clwe.executeClientWithPMS(invalidPMS);
            System.out.println(i + "th round");
        }
        System.out.println("done!");

        long delay;
        // train the oracle using the executeWorkflow functionality
        for (int i = 0; i < TRAINING_AMOUNT; i++) {
            delay = clwe.executeClientWithPMS(validPMS);
            validTimings.add(delay);

            delay = clwe.executeClientWithPMS(invalidPMS);
            invalidTimings.add(delay);

            System.out.print("\r left requests for training "
                    + (TRAINING_AMOUNT - i));
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
        boolean result = false;
        boolean groundTruth = false;

        counterOracle += 1;

        groundTruth = cheat(preMasterSecret);

        if (counterOracle < 792) {
            if (counterOracle % 100 == 0) {
                System.out.print("\r" + counterOracle);
            }
            if (groundTruth) {
                System.out.println(counterOracle + "TRUE!!!");
            }
            return groundTruth;
        }

        boolean test = isValidPKCS(preMasterSecret);

        if (!groundTruth) {
            if (!test) {
                /*
                 * all good!
                 */
                result = test;
            } else {
                /*
                 * The submitted key was invalid but our test predicted 
                 * that the key was valid. This is the worst case, because 
                 * it will most certainly break the subsequent computations. 
                 * We will stop here.
                 */
                System.err.println("ERROR: invalid key was predicted to "
                        + "be valid. Stopping.");
                result = test;
            }

        } else {
            if (!test) {
                /*
                 * The submitted key was valid but our test predicted that 
                 * the key was invalid. This decreases the performance of 
                 * the attack but does not necessarily break subsequent 
                 * computations.
                 */
                System.err.println("ERROR: valid key was predicted to "
                        + "be invalid. This decreases the attack "
                        + "performance.");
                result = test;
            } else {
                /*
                 * all good!
                 */
                result = test;
            }
        }

        System.out.println(counterOracle + ": Ground truth: "
                + groundTruth + ", timingoracle: " + result);

        return result;
    }

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
}
